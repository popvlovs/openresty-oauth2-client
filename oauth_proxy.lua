--
-- Created by Visual Studio Code.
-- User: yitian_song
-- Date: 2019/4/28
-- Time: 16:50
-- To make a OAuth2.0 client authorization proxy
-- 
-- Usage: Add config into nginx.conf as follows:
-- +---------------------------------------------------------------------------------------------------------------------------------------------+
-- | # oauth shared dict                                                                                                                         |
-- | lua_shared_dict oauth 10m;                                                                                                                  |
-- |                                                                                                                                             |
-- | # openresty lua lib                                                                                                                         |
-- | lua_package_path '/usr/local/openresty/lualib/?.lua;/usr/local/openresty/nginx/script/?.lua;/usr/local/openresty/nginx/script/lib/?.lua;';  |
-- | lua_package_cpath '/usr/local/openresty/lualib/?.so;';                                                                                      |
-- +---------------------------------------------------------------------------------------------------------------------------------------------+
-- 

local http = require "resty.http"
local config = require "oauth_config"
local cjson = require("cjson")
local string = require "string"
local resolver = require "resty.dns.resolver"
local httpc = http.new()
local urlParser = require "net.url"

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
    local url = string.format("%s?token=%s", config.checkTokenUri, access_token)
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

-- TODO: Validate TOKEN if exist
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
        ngx.log(ngx.INFO, "Current access token is: "..token)
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

-- TODO: Get username from access_token
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
    for _, regexp in pairs(config.permitUriRegexps) do
        if ngx.re.match(uri, regexp, "isjo") then
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
    ngx.log(ngx.INFO, string.format("Redirect to authorization entry point: %s", config.redirectUriEntrypoint))
    ngx.redirect(config.redirectUriEntrypoint)
end

-- Get access token by authorization code
local function get_access_token(authorizationCode)
    ngx.log(ngx.INFO, string.format("Request access token from OAuth server: %s", config.accessTokenUri))
    local grantType = "authorization_code"
    local clientId = config.clientId
    local clientSecret = config.clientSecret
    local redirectUri = config.host .. config.redirectUriEntrypoint
    local state = ngx.shared.oauth["csrfState"]
    local resp, err = httpc:request_uri(config.accessTokenUri, {
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
    return ngx.var.uri == config.redirectUriEntrypoint
end

-- Check is authentication code response
local function has_authorization_code()
    return ngx.var.arg_code ~= nil
end

-- Check is get current user request
local function is_get_current_user()
    for _, v in ipairs(config.getCurrentUserEndpoint) do
        if ngx.var.uri == v then
            return true
        end
    end
    return false
end

-- Check api should redirect header, to redirect api-request to its referer
local function should_redirect_to_referer()
    local headers = ngx.req.get_headers()
    local referer = urlParser.parse(ngx.var.http_referer or "/")
    return headers and headers["x-redirect-policy"] == "401-redirect-referer" and ngx.var.uri ~= referer.path
end

-- Redirect to referer or homepage
local function redirect_to_referer()
    local referer = ngx.var.http_referer or "/"
    ngx.log(ngx.INFO, string.format("Unauthorized web api request %s, policy is %s, redirect to its referer: %s", ngx.var.request_uri, ngx.req.get_headers()["x-redirect-policy"], referer))
    ngx.redirect(referer)
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
local function authorize()
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
            local authorizationRequst = config.userAuthorizationUri .. "?client_id=%s&redirect_uri=%s&response_type=code&state=%s"
            local clientId = config.clientId
            local redirectUri = config.host .. config.redirectUriEntrypoint
            local csrfState = randomString(6)
            ngx.shared.oauth["csrfState"] = csrfState
            authorizationRequst = string.format(authorizationRequst, clientId, redirectUri, csrfState)
            ngx.redirect(authorizationRequst)
        end
    elseif is_get_current_user() then
        -- Return current user
        local username = get_current_user()
        local result = { statusCode = 0, messages = {}, data = { user=username }, username=username }
        cjson.encode_empty_table_as_object(false)
        ngx.say(cjson.encode(result))
        return ngx.exit(ngx.status)
    elseif need_authorize(ngx.var.uri) then
        if should_redirect_to_referer() then
            -- Web api request, redirect to its referer as an authorization entrypoint
            redirect_to_referer()
        else
            -- Cache request and replay on authentication success
            ngx.shared.oauth["cachedRequest"] = ngx.var.request_uri
            ngx.log(ngx.INFO, string.format("Start authorization for requst: %s", ngx.var.request_uri))
            goto_authentication_entrypoint()
        end
    end
end

authorize()