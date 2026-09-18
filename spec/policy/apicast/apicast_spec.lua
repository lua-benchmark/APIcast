local _M = require 'apicast.policy.apicast'
local util = require("apicast.util")
local ssl = require('ngx.ssl')
local tls = require('resty.tls')
local X509_STORE = require('resty.openssl.x509.store')
local X509 = require('resty.openssl.x509')
local balancer = require('apicast.balancer')

describe('APIcast policy', function()
  local ngx_on_abort_stub

  before_each(function()
      -- .access calls ngx.on_abort
      -- busted tests are called in the context of ngx.timer
      -- and that API ngx.on_abort is disabled in that context.
      -- this stub is mocking the call
      -- to prevent the internal error: API disabled in the context of ngx.timer
      ngx_on_abort_stub = stub(ngx, 'on_abort')
  end)

  it('has a name', function()
    assert.truthy(_M._NAME)
  end)

  it('has a version', function()
    assert.truthy(_M._VERSION)
  end)

  describe('.access', function()
    it('stores in the context a flag that indicates that post_action should be run', function()
      local context = {}
      local apicast = _M.new()

      apicast:access(context)

      assert.is_true(context[apicast].run_post_action)
    end)
  end)

  describe(".balancer", function()
    local certificate_path = 't/fixtures/CA/root-ca.crt'
    local certificate_key_path = 't/fixtures/CA/root-ca.key'

    local certificate_content = util.read_file(certificate_path)
    local key_content = util.read_file(certificate_key_path)
    local ca_cert, _ = X509.new(certificate_content)

    local ca_store = X509_STORE.new()
    ca_store:add(ca_cert)

    local cert = ssl.parse_pem_cert(certificate_content)
    local key = ssl.parse_pem_priv_key(key_content)

    before_each(function()
      stub.new(balancer, 'call', function() return true end)
    end)

    it("correctly set certificate and key", function()
        local apicast = _M.new()
        local context = {
          upstream_certificate = cert,
          upstream_key = key,
        }

        spy.on(tls, "set_upstream_cert_and_key")
        apicast:balancer(context)
        assert.spy(tls.set_upstream_cert_and_key).was.called()
    end)

    it("ignore invalid certificate and key", function()
        local apicast = _M.new()
        local context = {
          upstream_certificate = nil,
          upstream_key = nil,
        }

        spy.on(tls, "set_upstream_cert_and_key")
        apicast:balancer(context)
        assert.spy(tls.set_upstream_cert_and_key).was_not.called()
    end)

    it("CA certificate is not used if verify is not enabled", function()
        local apicast = _M.new()
        local context = {
          upstream_certificate = cert,
          upstream_key = key,
          upstream_verify = false,
          upstream_ca_store = cert
        }

        spy.on(tls, "set_upstream_ca_store")
        apicast:balancer(context)
        assert.spy(tls.set_upstream_ca_store).was_not.called()
    end)

    it("CA certificate is used if verify is enabled", function()
        local apicast = _M.new()
        local context = {
          upstream_certificate = cert,
          upstream_key = key,
          upstream_verify = true,
          upstream_ca_store = ca_store.store
        }

        spy.on(tls, "set_upstream_ca_store")
        apicast:balancer(context)
        assert.spy(tls.set_upstream_ca_store).was_not.called()
    end)
  end)

  describe('.post_action', function()
    describe('when the "run_post_action" flag is set to true', function()
      it('runs its logic', function()
        -- A way to know whether the logic of the method run consists of
        -- checking if post_action() was called on the proxy of the context.

        local apicast = _M.new()
        local context = {
          proxy = { post_action = function() end },
          [apicast] = { run_post_action = true }
        }

        stub(context.proxy, 'post_action')

        apicast:post_action(context)

        assert.spy(context.proxy.post_action).was_called()
      end)
    end)

    describe('when the "run_post_action" flag is not set', function()
      it('does not run its logic', function()
        local apicast = _M.new()
        local context = {
          proxy = { post_action = function() end },
          [apicast] = { run_post_action = nil }
        }

        stub(context.proxy, 'post_action')

        apicast:post_action(context)

        assert.spy(context.proxy.post_action).was_not_called()
      end)
    end)
  end)
end)
