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
-- | lua_package_path '/usr/local/openresty/lualib/?.lua;/usr/local/openresty/nginx/script/?.lua;/usr/local/openresty/nginx/script lib/?.lua;';  |
-- | lua_package_cpath '/usr/local/openresty/lualib/?.so;';                                                                                      |
-- +---------------------------------------------------------------------------------------------------------------------------------------------+
-- 

local http = require "resty.http"
local config = require "oauth_config"
local cjson = require("cjson")
local string = require "string"
local resolver = require "resty.dns.resolver"
local httpc = http.new()

-- TODO: Validate TOKEN if exist
local function validate_token()
    local cookie = ngx.var.http_cookie
    if cookie == nil then
        return false
    end
    _, _, token = string.find(cookie, "ACCESS_TOKEN=(.*?);")
    if token ~= nil then
        return false
    end
    return true
    -- TODO: Check if exist in verified cache
    -- TODO: Remote check token
end

-- Check permit uri 
local function need_authorize(uri)
    if validate_token() then
        return
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
        local msg = "Invalid access: error on get access token, status=" .. resp.status .. ", body=" .. response.body
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
    elseif need_authorize(ngx.var.uri) then
        -- Cache request and replay on authentication success
        ngx.shared.oauth["cachedRequest"] = ngx.var.request_uri
        ngx.log(ngx.INFO, string.format("Start authorization for requst: %s", ngx.var.request_uri))
        goto_authentication_entrypoint()
    end
end

authorize()