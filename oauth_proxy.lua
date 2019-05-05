--
-- Created by Visual Studio Code.
-- User: yitian_song
-- Date: 2019/4/28
-- Time: 16:50
-- To make a OAuth2.0 client authorization proxy
-- 

local _M = {}
_M.config = require "oauth.oauth_config"

local http = require "resty.http"
local cjson = require("cjson")
local string = require "string"
local resolver = require "resty.dns.resolver"
local httpc = http.new()
local urlParser = require "net.url"

local function merge_config()
    if ngx.ctx.options then
        local _permitUriRegexps = _M.config.permitUriRegexps
        table.merge(_M.config, ngx.ctx.options)
        table.merge(_M.config.permitUriRegexps, _permitUriRegexps)
    end
end
merge_config()

-- Get user info from cache (throttle)
local function get_cached_userinfo()
    local cache = ngx.shared.oauth
    userInfo, _ = cache:get("userInfo")
    if userInfo ~= nil then
        return cjson.decode(userInfo)
    end
end

local function set_cached_userinfo(userinfo)
    local cache = ngx.shared.oauth
    cache:set("userInfo", userinfo)
end

-- Check access token and get user info
local function check_access_token(access_token)
    ngx.log(ngx.INFO, "Check access token from OAuth server")
    local url = string.format("%s?token=%s", _M.config.checkTokenUri, access_token)
    local resp, err = httpc:request_uri(url, {
        method = "GET"
    })
    if err then
        local msg = "Invalid access: error on get check token, " .. err
        ngx.log(ngx.ERR, msg)
        return false
    end
    if resp.status ~= 200 then
        local msg = "Invalid access: error on get check token, status=" .. resp.status .. ", body=" .. resp.body
        ngx.log(ngx.ERR, msg)
        return false
    end
    set_cached_userinfo(resp.body)
    return true
end

-- Validate TOKEN if exist
local function validate_token()
    local token = ngx.var.cookie_OAUTH_TOKEN
    if token == nil then
        return false
    end
    if token == nil then
        -- No token, go authorize
        ngx.log(ngx.INFO, "No access token, go authorize")
        return false
    else
        ngx.log(ngx.INFO, "Current access token is: **"..token:sub(-15))
    end

    local userInfo = get_cached_userinfo()
    if userInfo == nil then
        -- Token exist but no userInfo cache, start remote check
        ngx.log(ngx.INFO, "Token exist but cached user info missed, start check access_token")
        -- Check failed? go authorize
        local success = check_access_token(token)
        if not success then
            return false
        else
            userInfo = get_cached_userinfo()
            if userInfo == nil then
                return false
            end
        end
    end
    -- Token exist and userInfo exist, start expiration check
    local expired = userInfo["exp"] or userInfo["exipred"]
    if ngx.time() > expired then
        ngx.log(ngx.INFO, "The token has been expired in: "..tostring(expired))
        cache:delete("userInfo")
        return false
    end
    return true
end

-- Get username from access_token
local function get_current_user()
    local userInfo = get_cached_userinfo()
    if userInfo ~= nil then
        return userInfo["username"]
    end
    return "anonymousUser"
end

-- Check permit uri 
local function need_authorize(uri)
    if validate_token() then
        return false
    end
    for _, regexp in pairs(_M.config.permitUriRegexps) do
        if ngx.re.match(uri, regexp, "isjo") then
            ngx.log(ngx.INFO, string.format("Uri is permitted as %s, %s", regexp, uri))
            return false
        end
    end
    return true
end

local function split(str, regex)
    local t = {}
    for w in string.gmatch(str, "[^" .. regex .. "]+") do
        table.insert(t, w)
    end
    return t
end

-- Build http response
local function response(status, message)
    ngx.status = status
    local result = { status = status, message = message }
    ngx.say(cjson.encode(result))
    return ngx.exit(status)
end

-- Start OAuth flow
local function goto_authentication_entrypoint()
    ngx.log(ngx.INFO, string.format("Redirect to authorization entry point: %s", _M.config.redirectUriEntrypoint))
    ngx.redirect(_M.config.redirectUriEntrypoint)
end

-- Get access token by authorization code
local function get_access_token(authorizationCode)
    ngx.log(ngx.INFO, string.format("Request access token from OAuth server: %s", _M.config.accessTokenUri))
    local grantType = "authorization_code"
    local clientId = _M.config.clientId
    local clientSecret = _M.config.clientSecret
    local redirectUri = _M.config.host .. _M.config.redirectUriEntrypoint
    local state = ngx.shared.oauth["csrfState"]
    local resp, err = httpc:request_uri(_M.config.accessTokenUri, {
        method = "POST",
        body = string.format("grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s&state=%s", clientId, clientSecret, redirectUri, authorizationCode, state),
        headers = { 
            ["Content-Type"] = "application/x-www-form-urlencoded"
        }
    })
    if err then
        local msg = "Invalid access: error on get access token, " .. err
        ngx.log(ngx.ERR, msg)
        response(ngx.HTTP_UNAUTHORIZED, msg)
    end

    if resp.status ~= 200 then
        local msg = "Invalid access: error on get access token, status=" .. resp.status .. ", body=" .. resp.body
        ngx.log(ngx.ERR, msg)
        response(ngx.HTTP_UNAUTHORIZED, msg)
    end

    local json = cjson.decode(resp.body)
    return json["access_token"]
end

-- Check is authentication request
local function is_authentication_entrypoint()
    return ngx.var.uri == _M.config.redirectUriEntrypoint
end

-- Check is authentication code response
local function has_authorization_code()
    return ngx.var.arg_code ~= nil
end

-- Check is get current user request
local function is_current_user_request()
    for _, v in ipairs(_M.config.getCurrentUserEndpoint) do
        if ngx.var.uri == v then
            return true
        end
    end
    return false
end

-- Check HTTP header X-Redirect-Policy
local function should_redirect_to_referer()
    local headers = ngx.req.get_headers()
    local referer = urlParser.parse(ngx.var.http_referer or "/") 
    if headers and headers["x-redirect-policy"] then
        if ngx.var.uri ~= referer.path then
            ngx.log(ngx.INFO, "Find http-header [X-Redirect-Policy: "..headers["x-redirect-policy"].."], current uri: "..ngx.var.uri..", referer: "..referer.path..", will redirect to: "..referer.path)
        else
            ngx.log(ngx.INFO, "Find http-header [X-Redirect-Policy: "..headers["x-redirect-policy"].."], current uri: "..ngx.var.uri..", referer: "..referer.path..", end redirect loop")
        end
        return ngx.var.uri ~= referer.path
    else
        return false
    end
end

-- Redirect to referer or homepage
local function redirect_to_referer()
    local headers = ngx.req.get_headers()
    if not headers or not headers["x-redirect-policy"] then
        ngx.log(ngx.ERR, "Header X-Redirect-Policy not found!")
        return
    end
    local referer = ngx.var.http_referer or "/"
    if headers["x-redirect-policy"] == "401-redirect-referer" then
        -- Response 401, for "fetch" or other methods that cannot handle 302 redirect properly
        ngx.log(ngx.INFO, string.format("Response 401 with redirect url: %s", referer))
        local result = { statusCode = 3, messages = {}, data = { redirectUrl=referer } }
        cjson.encode_empty_table_as_object(false)
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say(cjson.encode(result))
        return ngx.exit(ngx.status)
    elseif headers["x-redirect-policy"] == "302-redirect-referer" then
        -- Response 302 redirect
        ngx.log(ngx.INFO, string.format("Redirect referer: %s", referer))
        ngx.redirect(referer)
    else
        ngx.log(ngx.ERR, "Undefined redirect policy: "..headers["x-redirect-policy"])
    end
end

-- Replay cached request
local function replay_cached_request()
    local request = "/"
    if ngx.shared.oauth["cachedRequest"] ~= nil then
        request = ngx.shared.oauth["cachedRequest"]
    end
    ngx.redirect(request)
end

-- Generate random string
local charset = {}  do -- [0-9a-zA-Z]
    for c = 48, 57  do table.insert(charset, string.char(c)) end
    for c = 65, 90  do table.insert(charset, string.char(c)) end
    for c = 97, 122 do table.insert(charset, string.char(c)) end
end

local function randomString(length)
    if not length or length <= 0 then return '' end
    math.randomseed(os.clock()^5)
    return randomString(length - 1) .. charset[math.random(1, #charset)]
end

-- Main authorization flow
function _M.authorize()
    if is_authentication_entrypoint() then
        if has_authorization_code() then
            -- Retrive authorization code
            local authorizationCode = ngx.var.arg_code
            -- Reqeust access_token
            local accessToken = get_access_token(authorizationCode)
            ngx.ctx.access_token = accessToken
            check_access_token(accessToken)
            replay_cached_request()
        else
            -- Authorize request
            local authorizationRequst = _M.config.userAuthorizationUri .. "?client_id=%s&redirect_uri=%s&response_type=code&state=%s"
            local clientId = _M.config.clientId
            local redirectUri = _M.config.host .. _M.config.redirectUriEntrypoint
            local csrfState = randomString(6)
            ngx.shared.oauth["csrfState"] = csrfState
            authorizationRequst = string.format(authorizationRequst, clientId, redirectUri, csrfState)
            ngx.redirect(authorizationRequst)
        end
    elseif is_current_user_request() then
        -- Intercept current user request
        local username = get_current_user()
        local result = { statusCode = 0, messages = {}, data = { user=username }, username=username }
        cjson.encode_empty_table_as_object(false)
        ngx.status = ngx.HTTP_OK
        ngx.say(cjson.encode(result))
        return ngx.exit(ngx.status)
    elseif need_authorize(ngx.var.uri) then
        if should_redirect_to_referer() then
            -- HTTP request (api call), redirect to its referer as an authorization entrypoint
            redirect_to_referer()
        else
            -- Cache request and replay on authentication success
            ngx.shared.oauth["cachedRequest"] = ngx.var.request_uri
            ngx.log(ngx.INFO, string.format("Start authorization for requst: %s", ngx.var.request_uri))
            goto_authentication_entrypoint()
        end
    end
end
return _M