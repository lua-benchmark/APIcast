use lib 't';
use Test::APIcast::Blackbox 'no_plan';

use Cwd qw(abs_path);

our $rsa = `cat t/fixtures/rsa.pem`;

run_tests();

__DATA__

=== TEST 1: Token introspection request success
Token introspection policy check access token.
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.req.read_body()
      local args, err = ngx.req.get_post_args()
      require('luassert').are.equal('testaccesstoken', args.token)
      ngx.say('{"active": true}')
    }
  }
--- configuration

{
  "services": [
    {
      "id": 42,
      "backend_version": "oidc",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_id+client_secret",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }

--- request
GET /echo
--- more_headers
Authorization: Bearer testaccesstoken
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Token already revoked.
Token introspection policy return "403 Unauthorized" if access token is already revoked on IdP.
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.say('{"active": false}')
    }
  }
--- configuration

{
  "services": [
    {
      "id": 42,
      "backend_version": "oidc",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_id+client_secret",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }

--- request
GET /echo
--- more_headers
Authorization: Bearer testaccesstoken
--- error_code: 403
--- no_error_log
[error]
--- error_log: token introspection for access token testaccesstoken: token not active



=== TEST 3: Token introspection request is failed due to IdP error
Token introspection policy return "403 Unauthorized" if IdP response error status.
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.exit(500)
    }
  }
--- configuration

{
  "services": [
    {
      "id": 42,
      "backend_version": "oidc",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_id+client_secret",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }

--- request
GET /echo
--- more_headers
Authorization: Bearer testaccesstoken
--- error_code: 403
--- no_error_log
[error]

=== TEST 4: Token introspection request is failed with bad response value
Token introspection policy return "403 Unauthorized" if IdP response invalid contents type.
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.req.read_body()
      local args, err = ngx.req.get_post_args()
      require('luassert').are.equal('testaccesstoken', args.token)
      ngx.say('<html></html>')
    }
  }
--- configuration

{
  "services": [
    {
      "id": 42,
      "backend_version": "oidc",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_id+client_secret",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }

--- request
GET /echo
--- more_headers
Authorization: Bearer testaccesstoken
--- error_code: 403
--- error_log
[error]

=== TEST 5: Token introspection request is failed with null response
Token introspection policy return "403 Unauthorized" if IdP null response .
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.req.read_body()
      local args, err = ngx.req.get_post_args()
      require('luassert').are.equal('testaccesstoken', args.token)
      ngx.say('null')
    }
  }
--- configuration

{
  "services": [
    {
      "id": 42,
      "backend_version": "oidc",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_id+client_secret",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }

--- request
GET /echo
--- more_headers
Authorization: Bearer testaccesstoken
--- error_code: 403
--- error_log
[error]

=== TEST 6: Token introspection request success with oidc issuer endpoint
Token introspection policy retrieves client_id and client_secret and
introspection endpoint from the oidc_issuer_endpoint of the service configuration.
--- backend
  location /token/introspection {
    content_by_lua_block {
      local credential = ngx.decode_base64(require('ngx.re').split(ngx.req.get_headers()['Authorization'], ' ', 'oj')[2])
      require('luassert').are.equal('app:appsec', credential)
      ngx.say('{"active": true}')
    }
  }

  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- configuration
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": {
        "id_token_signing_alg_values_supported": [ "RS256" ],
        "introspection_endpoint": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
      },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----", "alg": "RS256" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "use_3scale_oidc_issuer_endpoint"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with

=== TEST 7: Token introspection request fails with app_key
Token introspection policy retrieves client_id and client_secret and
introspection endpoint from the oidc_issuer_endpoint of the service configuration.
When authentication_method = 1, the request fails.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": "1",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "1",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "use_3scale_oidc_issuer_endpoint"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo?user_key=userkey
--- error_code: 403
--- response_body
Authentication failed
--- no_error_log
[error]
oauth failed with

=== TEST 8: Token introspection request success with oidc issuer endpoint loaded from the IDP
Token introspection policy retrieves client_id and client_secret and
introspection endpoint from the oidc_issuer_endpoint of the service configuration.
--- env eval
( 'APICAST_CONFIGURATION_LOADER' => 'lazy' )
--- backend
location = /issuer/endpoint/.well-known/openid-configuration {
  content_by_lua_block {
    local base = "http://" .. ngx.var.host .. ':' .. ngx.var.server_port
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say(require('cjson').encode {
        issuer = 'https://example.com/auth/realms/apicast',
        id_token_signing_alg_values_supported = { 'RS256' },
        jwks_uri = base .. '/jwks',
        introspection_endpoint = base .. '/token/introspection',
    })
  }
}

location = /jwks {
  content_by_lua_block {
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say([[
        { "keys": [
            { "kty":"RSA","kid":"somekid",
              "n":"sKXP3pwND3rkQ1gx9nMb4By7bmWnHYo2kAAsFD5xq0IDn26zv64tjmuNBHpI6BmkLPk8mIo0B1E8MkxdKZeozQ","e":"AQAB",
              "alg":"RS256" }
        ] }
    ]])
  }
}

location = /token/introspection {
  content_by_lua_block {
    local credential = ngx.decode_base64(require('ngx.re').split(ngx.req.get_headers()['Authorization'], ' ', 'oj')[2])
    require('luassert').are.equal('app:appsec', credential)
    ngx.say('{"active": true}')
  }
}

location = /transactions/oauth_authrep.xml {
  content_by_lua_block { ngx.exit(200) }
}

--- configuration
{
  "services": [
    {
      "backend_version": "oauth",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "use_3scale_oidc_issuer_endpoint"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with

=== TEST 9: Token introspection request success with oidc issuer endpoint returning deprecated introspection attribute
Token introspection policy retrieves client_id and client_secret and
introspection endpoint from the oidc_issuer_endpoint of the service configuration.
But the service configuration returns deprecated "token_introspection_endpoint" attribute
instead of "introspection_endpoint" attribute. This is for backward compatibility.

--- env eval
( 'APICAST_CONFIGURATION_LOADER' => 'lazy' )
--- backend
location = /issuer/endpoint/.well-known/openid-configuration {
  content_by_lua_block {
    local base = "http://" .. ngx.var.host .. ':' .. ngx.var.server_port
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say(require('cjson').encode {
        issuer = 'https://example.com/auth/realms/apicast',
        id_token_signing_alg_values_supported = { 'RS256' },
        jwks_uri = base .. '/jwks',
        token_introspection_endpoint = base .. '/token/introspection',
    })
  }
}

location = /jwks {
  content_by_lua_block {
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say([[
        { "keys": [
            { "kty":"RSA","kid":"somekid",
              "n":"sKXP3pwND3rkQ1gx9nMb4By7bmWnHYo2kAAsFD5xq0IDn26zv64tjmuNBHpI6BmkLPk8mIo0B1E8MkxdKZeozQ","e":"AQAB",
              "alg":"RS256" }
        ] }
    ]])
  }
}

location = /token/introspection {
  content_by_lua_block {
    local credential = ngx.decode_base64(require('ngx.re').split(ngx.req.get_headers()['Authorization'], ' ', 'oj')[2])
    require('luassert').are.equal('app:appsec', credential)
    ngx.say('{"active": true}')
  }
}

location = /transactions/oauth_authrep.xml {
  content_by_lua_block { ngx.exit(200) }
}

--- configuration
{
  "services": [
    {
      "backend_version": "oauth",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "use_3scale_oidc_issuer_endpoint"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with

=== TEST 10: Token introspection request success with oidc issuer endpoint
Token introspection policy retrieves introspection endpoint from the oidc_issuer_endpoint
of the service configuration. However, the introspection endpoint is not in the response
--- env eval
( 'APICAST_CONFIGURATION_LOADER' => 'lazy' )
--- backend
location = /issuer/endpoint/.well-known/openid-configuration {
  content_by_lua_block {
    local base = "http://" .. ngx.var.host .. ':' .. ngx.var.server_port
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say(require('cjson').encode {
        issuer = 'https://example.com/auth/realms/apicast',
        id_token_signing_alg_values_supported = { 'RS256' },
        jwks_uri = base .. '/jwks',
    })
  }
}

location = /jwks {
  content_by_lua_block {
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say([[
        { "keys": [
            { "kty":"RSA","kid":"somekid",
              "n":"sKXP3pwND3rkQ1gx9nMb4By7bmWnHYo2kAAsFD5xq0IDn26zv64tjmuNBHpI6BmkLPk8mIo0B1E8MkxdKZeozQ","e":"AQAB",
              "alg":"RS256" }
        ] }
    ]])
  }
}

--- configuration
{
  "services": [
    {
      "backend_version": "oauth",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "use_3scale_oidc_issuer_endpoint"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 403
--- no_error_log
[error]



=== TEST 11: Token introspection request success with client_secret_jwt method
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.req.read_body()
      local args, err = ngx.req.get_post_args()
      local assert = require('luassert')
      assert.same(args.client_id, "app")
      assert.same(args.client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      assert.is_not_nil(args.client_assertion)

      local resty_jwt = require "resty.jwt"
      local jwt_obj = resty_jwt:load_jwt(args.client_assertion)
      assert.same(jwt_obj.header.typ, "JWT")
      assert.same(jwt_obj.header.alg, "HS256")
      assert.same(jwt_obj.payload.sub, "app")
      assert.same(jwt_obj.payload.iss, "app")
      assert.same(jwt_obj.payload.aud, "http://test_backend/auth/realms/basic")
      assert.truthy(jwt_obj.signature)
      assert.truthy(jwt_obj.payload.jti)
      assert.truthy(jwt_obj.payload.exp)
      assert.is_true(jwt_obj.payload.exp > os.time())
      ngx.say('{"active": true}')
    }
  }

  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- configuration
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": {
        "id_token_signing_alg_values_supported": [ "RS256" ],
        "introspection_endpoint": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
      },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----", "alg": "RS256" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_secret_jwt",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection",
              "client_jwt_assertion_audience": "http://test_backend/auth/realms/basic"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with



=== TEST 12: Token introspection request failed with client_secret_jwt method
    and invalid token
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.say('{"active": false}')
    }
  }

  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- configuration
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": {
        "id_token_signing_alg_values_supported": [ "RS256" ],
        "introspection_endpoint": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
      },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----", "alg": "RS256" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "client_secret_jwt",
              "client_id": "app",
              "client_secret": "appsec",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection",
              "client_jwt_assertion_audience": "http://test_backend/auth/realms/basic"
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 403
--- response_body
Authentication failed
--- no_error_log
[error]
oauth failed with



=== TEST 13: Token introspection request success with private_key_jwt method
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.req.read_body()
      local args, err = ngx.req.get_post_args()
      local assert = require('luassert')
      assert.same(args.client_id, "app")
      assert.same(args.client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      assert.is_not_nil(args.client_assertion)

      local resty_jwt = require "resty.jwt"
      local jwt_obj = resty_jwt:load_jwt(args.client_assertion)
      assert.same(jwt_obj.header.typ, "JWT")
      assert.same(jwt_obj.header.alg, "RS256")
      assert.same(jwt_obj.payload.sub, "app")
      assert.same(jwt_obj.payload.iss, "app")
      assert.same(jwt_obj.payload.aud, "http://test_backend/auth/realms/basic")
      assert.truthy(jwt_obj.signature)
      assert.truthy(jwt_obj.payload.jti)
      assert.truthy(jwt_obj.payload.exp)
      assert.is_true(jwt_obj.payload.exp > os.time())
      ngx.say('{"active": true}')
    }
  }

  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- configuration
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": {
        "id_token_signing_alg_values_supported": [ "RS256" ],
        "introspection_endpoint": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
      },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----", "alg": "RS256" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "private_key_jwt",
              "client_id": "app",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection",
              "client_jwt_assertion_audience": "http://test_backend/auth/realms/basic",
              "certificate_type": "embedded",
              "certificate": "data:application/x-x509-ca-cert;name=rsa.pem;base64,LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCUEFJQkFBSkJBTENsejk2Y0RROTY1RU5ZTWZaekcrQWN1MjVscHgyS05wQUFMQlErY2F0Q0E1OXVzNyt1CkxZNXJqUVI2U09nWnBDejVQSmlLTkFkUlBESk1YU21YcU0wQ0F3RUFBUUpCQUpud1phNEJJQUNWZjhhUVhUb0EKSmhLdjkwYkZuMVRHMWJXMzhMSFRtUXM4RU05WENtZ2hMV0NqZTdkL05iVXJVY2VvdElPbmp0di94SFR5d0d0MgpOd0VDSVFEaHZNWkRRK1pSUmJid09OY3ZPOUc3aDZoRmd5MG9raXY2SmNpWmNjdnR4UUloQU1oVVRBV2dWMWhRCk8yeVdUUllSUVpvc0VJc0ZCM2taZnNMTWVUS2prOGRwQWlFQXNsc1o5Mm05bjNkS3JKRHNqRmhpUlI1Uk9PTUYKR2lvcjd4Qk5aOWUrdmRVQ0lEc2pmNG5OcXR0Y1hCNlRSRkIyYWFwc3hibDBrNTh4WXBWNUxYSkFqZmk1QWlFQQp2UmFTYXVCZlJDUDNKZ1hITmdjRFNXMDE3L0J0YndHaXo4YUlUdjZCMEZ3PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- user_files
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with



=== TEST 14: Token introspection request failed with private_key_jwt method
--- backend
  location /token/introspection {
    content_by_lua_block {
      ngx.say('{"active": false}')
    }
  }

  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- configuration
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": {
        "id_token_signing_alg_values_supported": [ "RS256" ],
        "introspection_endpoint": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection"
      },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----", "alg": "RS256" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "http://app:appsec@test_backend:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.token_introspection",
            "configuration": {
              "auth_type": "private_key_jwt",
              "client_id": "app",
              "introspection_url": "http://test_backend:$TEST_NGINX_SERVER_PORT/token/introspection",
              "client_jwt_assertion_audience": "http://test_backend/auth/realms/basic",
              "certificate_type": "embedded",
              "certificate": "data:application/x-x509-ca-cert;name=rsa.pem;base64,LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCUEFJQkFBSkJBTENsejk2Y0RROTY1RU5ZTWZaekcrQWN1MjVscHgyS05wQUFMQlErY2F0Q0E1OXVzNyt1CkxZNXJqUVI2U09nWnBDejVQSmlLTkFkUlBESk1YU21YcU0wQ0F3RUFBUUpCQUpud1phNEJJQUNWZjhhUVhUb0EKSmhLdjkwYkZuMVRHMWJXMzhMSFRtUXM4RU05WENtZ2hMV0NqZTdkL05iVXJVY2VvdElPbmp0di94SFR5d0d0MgpOd0VDSVFEaHZNWkRRK1pSUmJid09OY3ZPOUc3aDZoRmd5MG9raXY2SmNpWmNjdnR4UUloQU1oVVRBV2dWMWhRCk8yeVdUUllSUVpvc0VJc0ZCM2taZnNMTWVUS2prOGRwQWlFQXNsc1o5Mm05bjNkS3JKRHNqRmhpUlI1Uk9PTUYKR2lvcjd4Qk5aOWUrdmRVQ0lEc2pmNG5OcXR0Y1hCNlRSRkIyYWFwc3hibDBrNTh4WXBWNUxYSkFqZmk1QWlFQQp2UmFTYXVCZlJDUDNKZ1hITmdjRFNXMDE3L0J0YndHaXo4YUlUdjZCMEZ3PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /echo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- user_files
--- request
GET /echo
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 403
--- response_body
Authentication failed
--- no_error_log
[error]
oauth failed with
