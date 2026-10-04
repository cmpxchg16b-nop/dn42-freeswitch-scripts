-- dn42_msg_out.lua
-- local api = freeswitch.API()
-- local out = api:executeString("enum " .. message:getHeader("to_user") .. " tel.dn42")
-- local uri = out:match("(sip:%S+)")
-- if not uri then return end

-- local e = freeswitch.Event("CUSTOM", "SMS::SEND_MESSAGE")
-- e:addHeader("proto", "sip")
-- e:addHeader("dest_proto", "sip")
-- e:addHeader("sip_profile", message:getHeader("sip_profile") or "external-ipv6")
-- e:addHeader("from", message:getHeader("from"))
-- e:addHeader("from_full", "<sip:${dn42_e164_prefix}${from_user}@[${local_ip_v6}]>")
-- e:addHeader("sip_h_P-Asserted-Identity", "<sip:${dn42_e164_prefix}${from_user}@[${local_ip_v6}]>")
-- e:addHeader("to", uri)
-- e:addHeader("type", message:getHeader("type"))
-- e:addBody(message:getBody())
-- e:fire()


local api = freeswitch.API()

local function log(s)
    freeswitch.consoleLog("INFO", "[dn42dbg] " .. s .. "\n")
end

local to_user = message:getHeader("to_user")
local out = api:executeString("enum " .. tostring(to_user) .. " tel.dn42")
log("enum raw output >>>" .. tostring(out) .. "<<<")

-- 输出形如: sofia/external-ipv6/+042420929999@pbx.pebkac.dn42;transport=udp
local uri = out and out:match("sofia/[^/]+/([^;%s]+)")
if uri then
    uri = "sip:" .. uri
end
log("parsed uri=" .. tostring(uri))

if not uri then
    log("ABORT: no uri, nothing fired")
    return
end

local login = message:getHeader("login") or ""
local v6 = login:match("%[(.-)%]")
log("v6=" .. v6)

local sp = message:getHeader("sip_profile")
log("sip_profile(inbound)=" .. tostring(sp))

local dn42_e164_prefix = freeswitch.getGlobalVariable("dn42_e164_prefix")
log("dn42_e164_prefix=" .. tostring(dn42_e164_prefix))

local from_user = message:getHeader("from_user")
log("from_user=" .. tostring(from_user))

-- local local_ip_v6 = freeswitch.getGlobalVariable("local_ip_v6")
-- log("local_ip_v6" .. tostring(local_ip_v6))

local from_full = "<sip:" .. dn42_e164_prefix .. from_user .. "@[" .. v6 .. "]>"
log("from_full=" .. from_full)


local ctype = message:getHeader("type") or "text/plain"
local body = message:getBody() or ""
if ctype:lower():find("^message/cpim") then
    local mime = body:match("\r?\n\r?\n(.*)")               -- 去掉 CPIM 元数据头
    if mime then
        local mh, content = mime:match("^(.-)\r?\n\r?\n(.*)") -- 分离内层 MIME 头/正文
        if content then
            ctype = mh:match("[Cc]ontent%-[Tt]ype:%s*([^;%s]+)") or "text/plain"
            body = content:gsub("[%r%n]+$", "")
        end
    end
end

local e = freeswitch.Event("CUSTOM", "SMS::SEND_MESSAGE")
e:addHeader("proto", "sip")
e:addHeader("dest_proto", "sip")
e:addHeader("sip_profile", sp or "external-ipv6")
-- e:addHeader("sip_profile", "external-ipv6")
e:addHeader("from", message:getHeader("from"))
e:addHeader("from_full", from_full)
e:addHeader("sip_h_P-Asserted-Identity", from_full)
e:addHeader("to", uri)
e:addHeader("type", ctype)
e:addBody(body)
e:fire()
log("FIRED ok, to=" .. uri)
