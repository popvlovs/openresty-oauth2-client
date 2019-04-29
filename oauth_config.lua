--
-- Created by Visual Studio Code.
-- User: yitian_song
-- Date: 2019/4/28
-- Time: 16:50
-- OAuth2.0 Configurations
-- 

-- oauth server host
local oauthServerUrl = "https://oauth.hansight.com"

return {
    -- oauth client host (to make redirect uri)
    host = "http://52.81.79.12",
    -- oauth server authorize endpoint
    userAuthorizationUri = oauthServerUrl .. "/oauth/authorize",
    -- oauth server access token endpoint
    accessTokenUri = oauthServerUrl .. "/oauth/token",
    -- oauth server check token endpoint
    checkTokenUri = oauthServerUrl .. "/oauth/check_token",
    -- oauth client id
    clientId = "42c81db4-0afc-4b8f-8c76-f3b1252e91a7",
    -- oauth client secret
    clientSecret = "cb8539f3-aced-46bf-a44c-ab6e8d8e27c0",
    -- oauth client authorize entry point & redirect uri
    redirectUriEntrypoint = "/login",
    -- oauth client permit url(s), regular-expression supported
    permitUriRegexps = {
        -- important! permit redirect uri to avoid too many redirection error
        "/login",
        -- health check api
        "/healthz",
        -- static resource
        ".*\\..*"
    }
}