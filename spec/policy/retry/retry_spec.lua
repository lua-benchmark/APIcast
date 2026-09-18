local RetryPolicy = require('apicast.policy.retry')

describe('Retry policy', function()
  describe('.export', function()
    it('returns the the number of retries', function()
      local policy_config = { retries = 5, }
      local policy = RetryPolicy.new(policy_config)
      local context = {}

      policy:rewrite(context)

      assert.same(policy_config.retries, context.upstream_retries)
    end)
  end)
end)
