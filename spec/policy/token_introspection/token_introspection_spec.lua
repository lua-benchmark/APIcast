local TokenIntrospection = require('apicast.policy.token_introspection')
local TokensCache = require('apicast.policy.token_introspection.tokens_cache')
local format = string.format
local test_backend_client = require('resty.http_ng.backend.test')
local cjson = require('cjson')
local resty_jwt = require "resty.jwt"
local util = require 'apicast.util'

describe("token introspection policy", function()
  describe("execute introspection", function()
    local context
    local test_backend
    local test_access_token = "test"
    local test_client_id = "client"
    local test_client_secret = "secret"
    local test_basic_auth = 'Basic '..ngx.encode_base64(test_client_id..':'..test_client_secret)

    local function assert_authentication_failed()
      assert.same(ngx.status, 403)
      assert.stub(ngx.say).was.called_with("auth failed")
      assert.stub(ngx.exit).was.called_with(403)
    end

    before_each(function()
      test_backend = test_backend_client.new()
      ngx.var = {}
      ngx.var.http_authorization = "Bearer "..test_access_token
      ngx.var.request_id = "1234"
      context = {
        service = {
          auth_failed_status = 403,
          error_auth_failed = "auth failed"
        }
      }
    end)

    describe('client_id+client_secret introspection auth type', function()
      local auth_type = "client_id+client_secret"
      local introspection_url = "http://example/token/introspection"
      local policy_config = {
        auth_type = auth_type,
        introspection_url = introspection_url,
        client_id = test_client_id,
        client_secret = test_client_secret
      }

      it('success with valid token', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = cjson.encode({
                active = true
            })
          }

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('failed with invalid token', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = cjson.encode({
                active = false
            })
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()

        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('failed with bad status code', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 404,
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()

        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('failed with null response', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = 'null'
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()

        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('failed with active null response', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = '{ "active": null }'
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()

        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('failed with missing active response', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = '{}'
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()

        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('failed with bad contents type', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = "<html></html>"
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()

        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)
    end)

    describe('use_3scale_oidc_issuer_endpoint auth type', function()
      local auth_type = "use_3scale_oidc_issuer_endpoint"
      local policy_config = {
        auth_type = auth_type,
      }

      it('when no oauth content in the context', function()
        context = {
          service = {
            auth_failed_status = 403,
            error_auth_failed = "auth failed"
          },
          proxy = {
          }
        }

        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()
      end)

      it('using deprecated token_introspection_endpoint', function()
        test_backend
          .expect{
            url = "http://example.com/token/introspection",
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = cjson.encode({
                active = true
            })
          }
        context = {
          service = {
            auth_failed_status = 403,
            error_auth_failed = "auth failed",
            oidc = {
              issuer_endpoint = format('http://%s:%s@example.com/issuer/endpoint', test_client_id, test_client_secret)
            }
          },
          proxy = {
            oauth = {
              config = {
                token_introspection_endpoint = "http://example.com/token/introspection"
              }
            }
          }
        }

        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert.stub(ngx.exit).was_not.called_with(403)
        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

      it('using introspection_endpoint', function()
        test_backend
          .expect{
            url = "http://example.com/token/introspection",
            method = 'POST',
            headers = {
              ['Authorization'] = test_basic_auth
            }
          }
          .respond_with{
            status = 200,
            body = cjson.encode({
                active = true
            })
          }
        context = {
          service = {
            auth_failed_status = 403,
            error_auth_failed = "auth failed",
            oidc = {
              issuer_endpoint = format('http://%s:%s@example.com/issuer/endpoint', test_client_id, test_client_secret)
            }
          },
          proxy = {
            oauth = {
              config = {
                introspection_endpoint = "http://example.com/token/introspection",
                --- deprecated field
                token_introspection_endpoint = "http://example.com/token/deprecated_introspection"
              }
            }
          }
        }

        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert.stub(ngx.exit).was_not.called_with(403)
        assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
            { token = "test", token_type_hint = "access_token" })
      end)

    end)

    describe('client_secret_jwt introspection auth type', function()
      local auth_type = "client_secret_jwt"
      local introspection_url = "http://example/token/introspection"
      local audience = "http://example/auth/realm/basic"
      local policy_config = {
        auth_type = auth_type,
        introspection_url = introspection_url,
        client_id = test_client_id,
        client_secret = test_client_secret,
        client_jwt_assertion_audience = audience,
      }

      describe('success with valid token', function()
        local token_policy = TokenIntrospection.new(policy_config)
        before_each(function()
          test_backend
            .expect{
              url = introspection_url,
              method = 'POST',
            }
            .respond_with{
              status = 200,
              body = cjson.encode({
                  active = true
              })
            }
          token_policy.http_client.backend = test_backend
          token_policy:access(context)
        end)

        it('the request does not contains basic auth header', function()
          assert.is_nil(test_backend.get_requests()[1].headers['Authorization'])
        end)

        it('the request does not contains client_secret in body', function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          assert.is_nil(body.client_secret)
        end)

        it('the request contains correct fields in body', function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          assert.same(body.client_id, test_client_id)
          assert.same(body.client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
          assert.is_not_nil(body.client_assertion)
        end)

        it("has correct JWT headers", function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          local jwt_obj = resty_jwt:load_jwt(body.client_assertion)
          assert.same(jwt_obj.header.typ, "JWT")
          assert.same(jwt_obj.header.alg, "HS256")
        end)

        it("has correct JWT body", function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          local jwt_obj = resty_jwt:load_jwt(body.client_assertion)
          assert.same(jwt_obj.payload.sub, test_client_id)
          assert.same(jwt_obj.payload.iss, test_client_id)
          assert.truthy(jwt_obj.signature)
          assert.truthy(jwt_obj.payload.jti)
          assert.truthy(jwt_obj.payload.exp)
          assert.is_true(jwt_obj.payload.exp > os.time())
        end)
      end)

      it('failed with invalid token', function()
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
          }
          .respond_with{
            status = 200,
            body = cjson.encode({
                active = false
            })
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()
      end)
    end)

    describe('private_key_jwt introspection auth type', function()
      local auth_type = "private_key_jwt"
      local introspection_url = "http://example/token/introspection"
      local audience = "http://example/auth/realm/basic"
      local certificate_path = 't/fixtures/rsa.pem'
      local path_type = "path"
      local embedded_type = "embedded"

      describe("certificate validation", function()
        it("Reads correctly the file path", function()
          local policy_config = {
            auth_type = auth_type,
            introspection_url = introspection_url,
            client_id = test_client_id,
            client_jwt_assertion_audience = audience,
            certificate = certificate_path,
            certificate_type = path_type,
          }
          local token_policy = TokenIntrospection.new(policy_config)
          assert.truthy(token_policy.client_rsa_private_key)
        end)

        it("Read correctly the embedded path", function()
          local policy_config = {
            auth_type = auth_type,
            introspection_url = introspection_url,
            client_id = test_client_id,
            client_jwt_assertion_audience = audience,
            certificate_type = embedded_type,
            certificate = "data:application/x-x509-ca-cert;name=rsa.pem;base64,LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCUEFJQkFBSkJBTENsejk2Y0RROTY1RU5ZTWZaekcrQWN1MjVscHgyS05wQUFMQlErY2F0Q0E1OXVzNyt1CkxZNXJqUVI2U09nWnBDejVQSmlLTkFkUlBESk1YU21YcU0wQ0F3RUFBUUpCQUpud1phNEJJQUNWZjhhUVhUb0EKSmhLdjkwYkZuMVRHMWJXMzhMSFRtUXM4RU05WENtZ2hMV0NqZTdkL05iVXJVY2VvdElPbmp0di94SFR5d0d0MgpOd0VDSVFEaHZNWkRRK1pSUmJid09OY3ZPOUc3aDZoRmd5MG9raXY2SmNpWmNjdnR4UUloQU1oVVRBV2dWMWhRCk8yeVdUUllSUVpvc0VJc0ZCM2taZnNMTWVUS2prOGRwQWlFQXNsc1o5Mm05bjNkS3JKRHNqRmhpUlI1Uk9PTUYKR2lvcjd4Qk5aOWUrdmRVQ0lEc2pmNG5OcXR0Y1hCNlRSRkIyYWFwc3hibDBrNTh4WXBWNUxYSkFqZmk1QWlFQQp2UmFTYXVCZlJDUDNKZ1hITmdjRFNXMDE3L0J0YndHaXo4YUlUdjZCMEZ3PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
          }
          local token_policy = TokenIntrospection.new(policy_config)
          assert.truthy(token_policy.client_rsa_private_key)
        end)
      end)

      describe('success with valid token', function()
        local policy_config = {
          auth_type = auth_type,
          introspection_url = introspection_url,
          client_id = test_client_id,
          client_jwt_assertion_audience = audience,
          certificate = certificate_path,
          certificate_type = path_type,
        }
        before_each(function()
          test_backend
            .expect{
              url = introspection_url,
              method = 'POST',
            }
            .respond_with{
              status = 200,
              body = cjson.encode({
                  active = true
              })
            }
          local token_policy = TokenIntrospection.new(policy_config)
          token_policy.http_client.backend = test_backend
          token_policy:access(context)
        end)

        it('the request does not contains basic auth header', function()
          assert.is_nil(test_backend.get_requests()[1].headers['Authorization'])
        end)

        it('the request does not contains client_secret in body', function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          assert.is_nil(body.client_secret)
        end)

        it('the request contains correct fields in body', function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          assert.same(body.client_id, test_client_id)
          assert.same(body.client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
          assert.is_not_nil(body.client_assertion)
        end)

        it("has correct JWT headers", function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          local jwt_obj = resty_jwt:load_jwt(body.client_assertion)
          assert.same(jwt_obj.header.typ, "JWT")
          assert.same(jwt_obj.header.alg, "RS256")
        end)

        it("has correct JWT body", function()
          local body = ngx.decode_args(test_backend.get_requests()[1].body)
          local jwt_obj = resty_jwt:load_jwt(body.client_assertion)
          assert.same(jwt_obj.payload.sub, test_client_id)
          assert.same(jwt_obj.payload.iss, test_client_id)
          assert.truthy(jwt_obj.signature)
          assert.truthy(jwt_obj.payload.jti)
          assert.truthy(jwt_obj.payload.exp)
          assert.is_true(jwt_obj.payload.exp > os.time())
        end)
      end)

      it('failed with invalid token', function()
        local policy_config = {
          auth_type = auth_type,
          introspection_url = introspection_url,
          client_id = test_client_id,
          client_secret = test_client_secret,
          client_jwt_assertion_audience = audience,
          certificate_type= "path",
          certificate = certificate_path
        }
        test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
          }
          .respond_with{
            status = 200,
            body = cjson.encode({
                active = false
            })
          }
        stub(ngx, 'say')
        stub(ngx, 'exit')

        local token_policy = TokenIntrospection.new(policy_config)
        token_policy.http_client.backend = test_backend
        token_policy:access(context)
        assert_authentication_failed()
      end)
    end)

    describe('when caching is enabled', function()
      local introspection_url = "http://example/token/introspection"
      local policy_config = {
        auth_type = "client_id+client_secret",
        introspection_url = introspection_url,
        client_id = test_client_id,
        client_secret = test_client_secret,
        max_ttl_tokens = 120,
        max_cached_tokens = 10
      }

      local test_token_info = { active = true }
      local test_tokens_cache

      local token_policy = TokenIntrospection.new(policy_config)

      describe('and the token is cached', function()
        setup(function()
          test_tokens_cache = TokensCache.new(60)
          test_tokens_cache:set(test_access_token, test_token_info)
        end)

        it('does not call the introspection endpoint', function()
          token_policy.tokens_cache = test_tokens_cache
          token_policy.http_client.backend = { post = function () end }
          local http_client_spy = spy.on(token_policy.http_client.backend, 'post')

          token_policy:access(context)

          assert.spy(http_client_spy).was_not_called()
        end)
      end)

      describe('and the token is not cached', function()
        setup(function()
          test_tokens_cache = TokensCache.new(60)
        end)

        it('calls the introspection endpoint and caches the result', function()
          test_backend
          .expect{
            url = introspection_url,
            method = 'POST',
            headers = { ['Authorization'] = test_basic_auth }
          }
          .respond_with{ status = 200, body = cjson.encode(test_token_info) }

          token_policy.tokens_cache = test_tokens_cache
          token_policy.http_client.backend = test_backend

          token_policy:access(context)

          assert.same(test_token_info, test_tokens_cache:get(test_access_token))
          assert.are.same(ngx.decode_args(test_backend.get_requests()[1].body),
              { token = "test", token_type_hint = "access_token" })
        end)
      end)
    end)

    after_each(function()
      test_backend.verify_no_outstanding_expectations()
    end)
  end)
end)
