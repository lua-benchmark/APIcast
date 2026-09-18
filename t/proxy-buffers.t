use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: reject with 502 when upstream return large header (the header exceed the size
of proxy_buffer_size)
--- configuration env
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(ngx.OK)
    }
  }
--- upstream
  location / {
    content_by_lua_block {
        ngx.header["X-Large-Header"] = string.rep("a", 2^12)
    }
  }
--- request
GET /?user_key=value
--- error_code: 502
--- error_log eval
qr/upstream sent too big header while reading response header from upstream/


=== TEST 2: large utream header with APICAST_PROXY_BUFFER_SIZE set to 8k
--- env eval
(
  'APICAST_PROXY_BUFFER_SIZE' => '8k',
)
--- configuration env
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(ngx.OK)
    }
  }
--- upstream
  location / {
    content_by_lua_block {
        ngx.header["X-Large-Header"] = string.rep("a", 2^12)
    }
  }
--- request
GET /?user_key=value
--- response_headers eval
"X-Large-Header: " . ("a" x 4096) . "\r\n\r\n"
--- error_code: 200
--- no_error_log
[error]
