--
-- Created by Visual Studio Code.
-- User: yitian_song
-- Date: 2019/4/28
-- Time: 16:50
-- OAuth2.0 write TOKEN to Cookie
-- 

if ngx.ctx.access_token ~= nil then
    local cookie = string.format("OAUTH_TOKEN=%s; path=/;HttpOnly;", ngx.ctx.access_token)
    ngx.log(ngx.INFO, "Write access_token to Set-Cookie: "..string.format("OAUTH_TOKEN=**%s; path=/;HttpOnly;", ngx.ctx.access_token:sub(-15)))
    ngx.header["Set-Cookie"] = cookie
    ngx.ctx.access_token = nil
end