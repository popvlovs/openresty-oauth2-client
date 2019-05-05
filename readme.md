# Openresty OAuth2.0 集成手册
## 集成环境
### OAuth 客户端环境
- 客户端环境使用标准的Openresty集成包（ver: 1.11.2.3）：[ftp下载地址](ftp://ftp.nj.hansight.net/buildresource/saas/openresty_1.11.2.3.tgz)

### OAuth 认证服务器
- 当前仅对接Hansight统一认证中心 https://oauth.hansight.com
- 如需对接第三方OAuth认证服务，要进行一些改造（暂无需求）

## 集成步骤
- 将lua脚本拷贝到Openresty目录中，一般是
    ```shell
    \cp -rf oauth_config.lua oauth_proxy.lua oauth_success.lua lib /usr/local/openresty/nginx/script
    ```
- 修改nginx.conf

    ```nginx
    http {
        ...
        # 【在此添加】在Http段中添加下列配置，具体配置需随环境变化而调整
        # oauth shared dict
        lua_shared_dict oauth 10m;
        # openresty lua lib
        lua_package_path '/usr/local/openresty/lualib/?.lua;/usr/local/openresty/nginx/script/?.lua;/usr/local/openresty/nginx/script/lib/?.lua;';
        lua_package_cpath '/usr/local/openresty/lualib/?.so;';
        # set dns resolver
        resolver 172.31.38.183;
        # set lua ssl certification
        lua_ssl_verify_depth 2;
        lua_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;
        ...
        server {
            # 【在此添加】在Server段中应用lua脚本 oauth_proxy.lua
            access_by_lua_file  /usr/local/openresty/nginx/script/oauth_proxy.lua;
            # Blahblah...          
            proxy_http_version  1.1;
            proxy_set_header    Connection        "";
            proxy_set_header    Host              $host;
            proxy_set_header    X-Real-IP         $http_x_forwarded_for;
            proxy_set_header    X-Forwarded-For   $http_x_forwarded_for;
            proxy_set_header    Front-End-Https   on;
            proxy_set_header    X-Forwarded-Host  $host;
            proxy_set_header    X-Forwarded-Port  $server_port;
            proxy_set_header    X-Forwarded-Proto $scheme;
            proxy_intercept_errors on;
            proxy_read_timeout 300;
            proxy_connect_timeout 300;
            proxy_pass          http://webservice$request_uri;
            # 【在此添加】在Server段中应用lua脚本 oauth_success.lua
            header_filter_by_lua_file /usr/local/openresty/nginx/script/oauth_success.lua;
        }
    }
    ```
    `resolver` 配置可通过下列指令查看（Centos）
    ```shell
    cat /etc/resolv.conf | grep nameserver
    ```
    `ssl证书库`的位置可通过下列指令查看
    ```shell
    curl -vsk https://oauth.hansight.com

    ...
    * successfully set certificate verify locations:
    *   CAfile: /etc/pki/tls/certs/ca-bundle.crt  <----- Find CAfile here
    ...
    ```
- 在Hansight统一认证中心中创建应用
    - [Hansight统一认证中心](https://oauth-admin.hansight.com)，没有权限的话可以找管理员添加（yitian_song@hansight.com）

- 修改配置文件oauth_config.lua
    ```lua
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
        -- oauth client get current user endpoint
        getCurrentUserEndpoint = { "/system/user/current", "_api/current/user" },
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
    ```
    - 一般需要改的是`host`，`clientId` 与 `clientSecret`
    - `permitUriRegexps`视情况添加