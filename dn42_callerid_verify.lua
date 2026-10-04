-- dn42_callerid_verify.lua
--
-- 主叫防伪校验（dn42 / E.164 / ENUM）：
--   1. 从 P-Asserted-Identity（优先）或 From 提取 dn42 E.164 号码（+042 开头）
--   2. 对该号码做 ENUM 查询（tel.dn42），得到对方 PBX 的 host；
--      host 是域名则解析 AAAA，这组 IPv6 地址即 source of truth
--   3. 与网络层来源 IP 归一化后交叉比对
--
-- verdict = "true" / "false" / "unknown"。unknown 的几种情形：
--   caller id 里没有 +042 号码、ENUM 无记录、域名解析不出 AAAA、
--   事件里没有可用的来源 IP 头、来源是 IPv4（truth 只含 v6）。
--   unknown 不等于通过，处置策略由调用方决定。
--
-- 注意：chatplan 的 MESSAGE 事件是否携带 socket 层来源 IP 头取决于
-- FreeSWITCH 版本，脚本按候选列表逐个探测并在日志里注明实际命中了
-- 哪个头；呼叫场景（session）下 sip_network_ip 是可靠的来源。
--
-- 用法 A：dialplan / chatplan 里直接 lua dn42_callerid_verify.lua
--   - 有 session（呼叫）：结果写通道变量
--       dn42_src_e164 / dn42_src_ip / dn42_src_truth / dn42_src_verified
--     后续可配 <condition field="${dn42_src_verified}" expression="^true$">
--   - 有 message（SIP MESSAGE）：结果写日志，并触发 CUSTOM 事件
--       dn42::callerid_check（带 e164/src_ip/truth/verified 头）
--
-- 用法 B：作为库被其他 lua 脚本 dofile，比如在发 SMS::SEND_MESSAGE 前 gate：
--   DN42_VERIFY_LIB = true
--   local v = dofile("/usr/local/freeswitch/scripts/dn42_callerid_verify.lua")
--   local e164 = v.extract_e164(message:getHeader("P-Asserted-Identity")
--                or message:getHeader("from_full"))
--   local verdict, truth = v.check(e164, message:getHeader("network_ip"))
--   if verdict ~= "true" then log("reject: " .. verdict) return end
--
-- 依赖：域名解析走系统命令 getent ahostsv6，失败回退 dig +short AAAA
-- （Lua 标准库没有 DNS 能力）；host 做了字符白名单防止 shell 注入。

local api = freeswitch.API()

local ENUM_ROOT      = "tel.dn42"
local NET_IP_HEADERS = { "sip_network_ip", "network_ip", "from_sip_ip" }

local function log(s)
    freeswitch.consoleLog("INFO", "[dn42verify] " .. tostring(s) .. "\n")
end

---------- IP 归一化（v6 展开成小写全格式，比对才可靠） ----------
local function norm_ip(ip)
    if not ip then return nil end
    ip = tostring(ip):lower()
    ip = ip:gsub("^(%[[%x:%.]+%]):%d+$", "%1")          -- [v6]:port -> [v6]
    ip = ip:gsub("^(%d+%.%d+%.%d+%.%d+):%d+$", "%1")    -- v4:port -> v4
    ip = ip:gsub("^%[", ""):gsub("%]$", "")             -- 去方括号
    ip = ip:gsub("%%.+$", "")                           -- 去 zone id
    if ip:match("^%d+%.%d+%.%d+%.%d+$") then return ip end  -- v4 原样
    if not ip:find(":") or ip:find("%.") then return ip end -- v4-mapped 混合形式不碰
    local groups = {}
    local head, tail = ip:match("^(.-)::(.*)$")
    if head then
        local hn = 0
        for g in head:gmatch("[^:]+") do groups[#groups+1] = g; hn = hn + 1 end
        local tg = {}
        for g in tail:gmatch("[^:]+") do tg[#tg+1] = g end
        for _ = 1, 8 - hn - #tg do groups[#groups+1] = "0" end
        for _, g in ipairs(tg) do groups[#groups+1] = g end
    else
        for g in ip:gmatch("[^:]+") do groups[#groups+1] = g end
    end
    if #groups ~= 8 then return ip end
    for i, g in ipairs(groups) do
        local n = tonumber(g, 16)
        if not n then return ip end
        groups[i] = string.format("%04x", n)
    end
    return table.concat(groups, ":")
end

local function is_ip_literal(host)
    return host:match("^%d+%.%d+%.%d+%.%d+$") ~= nil or host:find(":") ~= nil
end

---------- 从 PAI / From 提取 dn42 E.164（+042 开头） ----------
local function extract_e164(s)
    if not s then return nil end
    s = tostring(s)
    local user = s:match("sip:([^@>;]+)@")
              or s:match("tel:([^>;]+)")
              or s:match("^%s*<?([^@>;]+)@")
    if not user then return nil end
    user = user:gsub("[^%d%+]", ""):gsub("^%+", "")
    if user:match("^%d+$") and user:sub(1, 3) == "042" then
        return "+" .. user
    end
    return nil
end

---------- ENUM 查询，解析出所有 URI ----------
local function enum_uris(e164)
    local num = e164:gsub("%D", "")
    local out = api:executeString("enum " .. num .. " " .. ENUM_ROOT)
    log("enum " .. num .. " " .. ENUM_ROOT .. " >>>" .. tostring(out) .. "<<<")
    local uris = {}
    for line in tostring(out or ""):gmatch("[^\r\n]+") do
        local u = line:match("sofia/[^/]+/([^;%s]+)")
               or line:match("(sip:[^;%s>]+)")
               or line:match("([%+%d][%d]*@[^;%s>]+)")
        if u then uris[#uris+1] = u end
    end
    return uris
end

local function host_of(uri)
    return uri:match("@%[([%x:%.]+)%]")          -- @[v6]
        or uri:match("@([%w%.%-]+)")             -- @domain 或 @v4
        or uri:match("^sip:%[?([%x:%.]+)%]?$")   -- 无 user 部分
end

---------- 域名 -> AAAA（getent 优先，dig 兜底） ----------
local function resolve_v6(host)
    local ips, seen = {}, {}
    local function grab(out)
        for line in tostring(out or ""):gmatch("[^\r\n]+") do
            local f = line:match("^%s*(%S+)")
            if f and f:find(":") and not f:find("%.") then
                local n = norm_ip(f)
                if n and not seen[n] then seen[n] = true; ips[#ips+1] = n end
            end
        end
    end
    if not host:match("^[%w%.%-]+$") then
        log("WARN: host 含非法字符，跳过解析: " .. host)
        return ips
    end
    local fh = io.popen('getent ahostsv6 "' .. host .. '" 2>/dev/null')
    if fh then grab(fh:read("*a")); fh:close() end
    if #ips == 0 then
        fh = io.popen('dig +short AAAA "' .. host .. '" 2>/dev/null')
        if fh then grab(fh:read("*a")); fh:close() end
    end
    return ips
end

---------- 号码 -> source of truth（IPv6 集合 + 展示列表） ----------
local function truth_for(e164)
    local set, list, seen = {}, {}, {}
    for _, u in ipairs(enum_uris(e164)) do
        local host = host_of(u)
        if host then
            if is_ip_literal(host) then
                local n = norm_ip(host)
                if not seen[n] then seen[n] = true; set[n] = true; list[#list+1] = n end
            else
                local ips = resolve_v6(host)
                if #ips == 0 then
                    log("WARN: " .. host .. " 解析不出 AAAA")
                    list[#list+1] = host .. "(unresolved)"
                end
                for _, n in ipairs(ips) do
                    if not seen[n] then seen[n] = true; set[n] = true; list[#list+1] = n end
                end
            end
        end
    end
    return set, list
end

---------- 校验主流程 ----------
local function check(e164, net_ip)
    if not e164 then
        log("caller id 里没有 +042 开头的 dn42 号码")
        return "unknown", {}
    end
    local set, list = truth_for(e164)
    local nip = norm_ip(net_ip)
    local verdict = "unknown"
    if not nip then
        log("WARN: 没有可用的网络层来源 IP，无法比对")
    elseif not nip:find(":") then
        log("WARN: 来源是 IPv4 (" .. nip .. ")，truth 只含 v6，跳过比对")
    elseif not next(set) then
        log("WARN: truth 为空（ENUM 无记录或解析失败），无法比对")
    else
        verdict = set[nip] and "true" or "false"
    end
    log(string.format("e164=%s src=%s truth={%s} verdict=%s",
        e164, tostring(net_ip), table.concat(list, ","), verdict))
    return verdict, list
end

---------- 同时兼容 session / message 两种上下文的取头函数 ----------
local function hdr(names)
    for _, n in ipairs(names) do
        local v
        if session then
            v = session:getVariable(n) or session:getVariable("sip_h_" .. n)
        elseif message then
            v = message:getHeader(n) or message:getHeader("sip_h_" .. n)
        end
        if v and v ~= "" then return v, n end
    end
    return nil
end

local M = {
    extract_e164 = extract_e164,
    norm_ip      = norm_ip,
    truth_for    = truth_for,
    check        = check,
}

---------- 直接作为脚本运行（dofile 库模式时跳过） ----------
if not DN42_VERIFY_LIB then
    local pai, pai_h = hdr({ "P-Asserted-Identity", "p_asserted_identity" })
    local frm, frm_h = hdr({ "sip_from_uri", "from_full", "from" })
    if pai then log("PAI(" .. tostring(pai_h) .. ")=" .. pai) end
    if frm then log("From(" .. tostring(frm_h) .. ")=" .. frm) end

    local e164 = extract_e164(pai) or extract_e164(frm)
    local net_ip, ip_h = hdr(NET_IP_HEADERS)
    if net_ip then
        log("net ip from header " .. ip_h .. " = " .. net_ip)
    else
        log("WARN: 事件里没有来源 IP 头（候选: " .. table.concat(NET_IP_HEADERS, "/") .. "）")
    end

    local verdict, list = check(e164, net_ip)
    local truth_s = table.concat(list or {}, ",")

    if session then
        session:setVariable("dn42_src_e164", tostring(e164 or ""))
        session:setVariable("dn42_src_ip", tostring(net_ip or ""))
        session:setVariable("dn42_src_truth", truth_s)
        session:setVariable("dn42_src_verified", verdict)
    elseif message then
        local e = freeswitch.Event("CUSTOM", "dn42::callerid_check")
        e:addHeader("e164", tostring(e164 or ""))
        e:addHeader("src_ip", tostring(net_ip or ""))
        e:addHeader("truth", truth_s)
        e:addHeader("verified", verdict)
        e:fire()
    end
end

return M
