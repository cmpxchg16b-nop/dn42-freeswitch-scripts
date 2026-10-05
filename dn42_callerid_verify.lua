-- dn42_callerid_verify.lua
--
-- dn42 主叫防伪校验 + 本地分机号保护：
--   1. 从 P-Asserted-Identity（优先）或 From 提取 caller id 用户部分
--   2. 本地分机保护：caller id 匹配 LOCAL_EXT_PATTERN（默认 ^10[0-9]{2}$）的，
--      只有 INTERNAL_PROFILES 有资格使用；外部 profile 冒用即拒
--   3. dn42 校验：caller id 是 +042 号码时，ENUM 反查对方 PBX host，解析 AAAA
--      得到 source of truth，与网络层来源 IP 归一化后交叉比对
--   4. 策略终判：STRICT_PROFILES（external / external-ipv6）为严格模式——
--      verdict 必须 true；false 和 unknown（含 ENUM 无记录、对面 DNS 解析
--      失败、取不到来源 IP 头）一律拒。对面 DNS 的问题对面自己解决。
--
-- 输出（message 头 / 通道变量）：
--   dn42_src_e164      提取到的 +042 号码（无则空）
--   dn42_src_ip        网络层来源 IP
--   dn42_src_truth     source of truth 地址列表
--   dn42_src_verified  原始校验结果 true / false / unknown
--   dn42_src_allow     策略终判 true / false   ← chatplan 门控用这个
--   dn42_src_reason    ok / internal_ext / spoofed_local_ext /
--                      verify_failed / verify_inconclusive / unverified
--
-- 注意：chatplan 的 MESSAGE 事件是否携带 socket 层来源 IP 头取决于
-- FreeSWITCH 版本，脚本按候选列表逐个探测并在日志里注明实际命中了
-- 哪个头。严格模式下取不到来源 IP 头 = unknown = 拒，不会静默放行。
--
-- chatplan 接线（放在所有业务 extension 之前）：
--   <extension name="dn42_callerid_verify" continue="true">
--     <condition field="${sip_profile}" expression="^(external|external-ipv6)$"/>
--     <condition field="to" expression="^(.*)$">
--       <action application="lua" data="dn42_callerid_verify.lua"/>
--     </condition>
--   </extension>
--   <extension name="dn42_callerid_gate">
--     <condition field="${dn42_src_allow}" expression="^false$">
--       <action application="info"/>
--       <action application="stop"/>
--     </condition>
--   </extension>
--   内部 profile 不匹配第一个 extension，脚本不跑、dn42_src_allow 为空，
--   gate 自然放行。
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

local ENUM_ROOT         = "tel.dn42"
local NET_IP_HEADERS    = { "sip_network_ip", "network_ip", "from_sip_ip" }
local LOCAL_EXT_PATTERN = "^10[0-9]{2}$"
local INTERNAL_PROFILES = { ["internal"] = true, ["internal-ipv6"] = true }
local STRICT_PROFILES   = { ["external"] = true, ["external-ipv6"] = true }

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

---------- caller id 用户部分提取（PAI / From 通用） ----------
local function extract_user(s)
    if not s then return nil end
    s = tostring(s)
    local user = s:match("sip:([^@>;]+)@")
              or s:match("tel:([^>;]+)")
              or s:match("^%s*<?([^@>;]+)@")
    if not user then return nil end
    user = user:gsub("[^%d%+]", ""):gsub("^%+", "")
    if user:match("^%d+$") then return user end
    return nil
end

---------- dn42 E.164（+042 开头） ----------
local function extract_e164(s)
    local user = extract_user(s)
    if user and user:sub(1, 3) == "042" then
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

---------- ENUM 校验主流程（不含策略） ----------
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
        if v and v ~= "" then return v end
    end
    return nil
end

local M = {
    extract_user = extract_user,
    extract_e164 = extract_e164,
    norm_ip      = norm_ip,
    truth_for    = truth_for,
    check        = check,
}

---------- 直接作为脚本运行（dofile 库模式时跳过） ----------
if not DN42_VERIFY_LIB then
    local pai = hdr({ "P-Asserted-Identity", "p_asserted_identity" })
    local frm = hdr({ "sip_from_uri", "from_full", "from" })
    local profile = hdr({ "sip_profile" })
    if pai then log("PAI=" .. pai) end
    if frm then log("From=" .. frm) end
    log("sip_profile=" .. tostring(profile))

    local e164 = extract_e164(pai) or extract_e164(frm)
    local net_ip = hdr(NET_IP_HEADERS)
    if net_ip then log("net ip=" .. net_ip)
    else log("WARN: 事件里没有来源 IP 头（候选: " .. table.concat(NET_IP_HEADERS, "/") .. "）") end

    -- 本地分机号检查：PAI 和 From 分别查，任一中招即算
    local function is_local_ext(u)
        return u ~= nil and u:match(LOCAL_EXT_PATTERN) ~= nil
    end
    local ext_pai = is_local_ext(extract_user(pai))
    local ext_frm = is_local_ext(extract_user(frm))

    local verdict, allow, reason, list = "unknown", true, "unverified", {}

    if ext_pai or ext_frm then
        -- caller id 是本地分机号：只有内部 profile 有资格
        if INTERNAL_PROFILES[profile] then
            reason = "internal_ext"
        else
            verdict, allow, reason = "false", false, "spoofed_local_ext"
        end
    else
        verdict, list = check(e164, net_ip)
        if verdict == "true" then
            allow, reason = true, "ok"
        elseif verdict == "false" then
            allow, reason = false, "verify_failed"
        elseif STRICT_PROFILES[profile] then
            -- 严格模式：unknown 也拒（ENUM 无记录 / DNS 故障 / 无来源 IP）
            allow, reason = false, "verify_inconclusive"
        else
            allow, reason = true, "unverified"
        end
    end

    local truth_s = table.concat(list or {}, ",")
    log(string.format("policy: profile=%s verdict=%s allow=%s reason=%s",
        tostring(profile), verdict, tostring(allow), reason))

    local fields = {
        dn42_src_e164     = tostring(e164 or ""),
        dn42_src_ip       = tostring(net_ip or ""),
        dn42_src_truth    = truth_s,
        dn42_src_verified = verdict,
        dn42_src_allow    = tostring(allow),
        dn42_src_reason   = reason,
    }

    if session then
        for k, v in pairs(fields) do session:setVariable(k, v) end
    elseif message then
        -- 写回 message 头，chatplan 后续 extension 的 condition 才能读到
        local ok, err = pcall(function()
            for k, v in pairs(fields) do
                message:chat_execute("set", k .. "=" .. v)
            end
        end)
        if not ok then
            log("WARN: chat_execute(set) 不可用: " .. tostring(err))
        end
        local e = freeswitch.Event("CUSTOM", "dn42::callerid_check")
        for k, v in pairs(fields) do
            e:addHeader((k:gsub("^dn42_src_", "")), v)
        end
        e:fire()
    end
end

return M