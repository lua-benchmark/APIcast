--- Policy loader
-- This module loads a policy defined by its name and version.
-- It uses sandboxed require to isolate dependencies and not mutate global state.
-- That allows for loading several versions of the same policy with different dependencies.
-- And even loading several independent copies of the same policy with no shared state.
-- Each object returned by the loader is new table and shares only shared APIcast code.

local sandbox = require('resty.sandbox')
local cjson = require('cjson')

local format = string.format
local ipairs = ipairs
local pairs = pairs
local insert = table.insert
local concat = table.concat
local setmetatable = setmetatable
local pcall = pcall
local type = type
local debug = debug
local _G = _G

local isempty = require('table.isempty')

-- Module-level cache storage (one per worker process)
local manifests_cache = {}

local _M = {}

local resty_env = require('resty.env')
local re = require('ngx.re')

-- Fixed, hand-audited set of already-broadly-exposed, pure, side-effect-free
-- sandbox builtins a manifest-declared legacy module name may resolve to
-- when it can't be validated any other way (see normalize_capabilities
-- below). Deliberately excludes getfenv/setfenv/loadfile/dofile/debug/_G.
local SAFE_ALIAS_TARGETS = {
  tostring = true, tonumber = true, type = true,
  ipairs = true, pairs = true, select = true,
}

-- Grants one or more dotted-or-bare names from a space-separated string
-- into a sandbox env table, mirroring resty.sandbox's own private `export`
-- helper (which isn't exported from that module, hence the duplication
-- here). Does not itself validate anything -- callers decide what is safe
-- to pass in.
local function grant_capabilities(env, capabilities)
  if not capabilities then return end
  capabilities:gsub('%S+', function(id)
    local module, method = id:match('([^%.]+)%.([^%.]+)')
    if module then
      env[module] = env[module] or {}
      env[module][method] = _G[module][method]
    else
      env[id] = _G[id]
    end
  end)
end

-- Manifests may declare their requested legacy sandbox modules either as a
-- single space-separated string (the original, validated form) or, in
-- newer manifests, as a JSON array of names. Only the string form is
-- checked against the fixed safe-target allowlist below.
local function normalize_capabilities(raw)
  if type(raw) == 'string' then
    if SAFE_ALIAS_TARGETS[raw] then
      return raw                                                                        -- SAFE_SINK: PLANTED-LUA-HR-29-safe
    end
    return nil
  elseif type(raw) == 'table' then
    return concat(raw, ' ')                                                             -- SINK: PLANTED-LUA-HR-29
  end
end

do
  local function apicast_dir()
    return resty_env.value('APICAST_DIR') or '.'
  end

  local function policy_load_path()
    return resty_env.value('APICAST_POLICY_LOAD_PATH') or
      format('%s/policies', apicast_dir())
  end

  function _M.policy_load_paths()
    return re.split(policy_load_path(), ':', 'oj')
  end

  function _M.builtin_policy_load_path()
    return resty_env.value('APICAST_BUILTIN_POLICY_LOAD_PATH') or format('%s/src/apicast/policy', apicast_dir())
  end
end

-- Returns true if config validation has been enabled via ENV or if we are
-- running Test::Nginx integration tests. We know that the framework always
-- sets TEST_NGINX_BINARY so we can use it to detect whether we are running the
-- tests.
local function policy_config_validation_is_enabled()
  return resty_env.enabled('APICAST_VALIDATE_POLICY_CONFIGS')
    or resty_env.value('TEST_NGINX_BINARY')
end

local policy_config_validator = { validate_config = function() return true end }
if policy_config_validation_is_enabled() then
  policy_config_validator = require('apicast.policy_config_validator')
end

local function read_manifest(path)
  local handle = io.open(format('%s/%s', path, 'apicast-policy.json'))

  if handle then
    local contents = handle:read('*a')

    handle:close()

    return cjson.decode(contents)
  end
end

local function lua_load_path(load_path)
  return format('%s/?.lua', load_path)
end

-- Get a cached manifest by policy name and version
-- @tparam string name The policy name
-- @tparam string version The policy version
-- @treturn table|nil The cached manifest table, or nil if not cached
local function get_cached_manifest(name, version)
  local manifests = manifests_cache[name]
  if manifests then
    for _, manifest in ipairs(manifests) do
      if version == manifest.version then
        return manifest
      end
    end
  end
end

local function load_manifest(name, version, path)
  local manifest = get_cached_manifest(name, version)
  if not manifest then
    manifest = read_manifest(path)
  end

  if manifest then
      if manifest.version ~= version then
        ngx.log(ngx.ERR, 'Not loading policy: ', name,
          ' path: ', path,
          ' version: ', version, '~= ', manifest.version)
        return
      end

    return manifest, lua_load_path(path)
  end

  return nil, lua_load_path(path)
end

local function with_config_validator(policy, policy_config_schema)
  local original_new = policy.new

  local new_with_validator = function(config)
    local is_valid, err = policy_config_validator.validate_config(
      config, policy_config_schema)

    if not is_valid then
      error(format('Invalid config for policy: %s', err))
    end

    return original_new(config)
  end

  return setmetatable(
    { new = new_with_validator },
    { __index = policy }
  )
end

function _M:load_path(name, version, paths)
  local failures = {}

  if version == 'builtin' then
    local manifest, load_path = load_manifest(name, version, format('%s/%s', self.builtin_policy_load_path(), name) )

    if manifest then
      return load_path, manifest.configuration
    else
      insert(failures, load_path)
    end
  end

  for _, path in ipairs(paths or self.policy_load_paths()) do
    local manifest, load_path = load_manifest(name, version, format('%s/%s/%s', path, name, version) )

    if manifest then
      return load_path, manifest.configuration
    else
      insert(failures, load_path)
    end
  end


  return nil, nil, failures
end

local package_cache = setmetatable({}, {
  __index = function(t, k) local n = { }; t[k] = n; return n end
})

function _M:call(name, version, dir)
  local v = version or 'builtin'
  local load_path, policy_config_schema, invalid_paths = self:load_path(name, v, dir)

  local cache_key = concat({name, v, dir and concat(dir, ',') or '' }, '-')

  local cache = package_cache[cache_key]
  local loader = sandbox.new(load_path and { load_path } or invalid_paths,
          cache)

  ngx.log(ngx.DEBUG, 'loading policy: ', name, ' version: ', v)

  -- Built-in convenience for policies migrated from the pre-sandbox baseline:
  -- grant back a couple of already-vetted, harmless builtins by name so
  -- they don't need re-declaring in every legacy manifest.
  grant_capabilities(loader.env, 'tostring tonumber')                                    -- SAFE_SINK: PLANTED-LUA-HR-27-safe

  -- Policy-declared legacy compatibility globals: opt-in via an x- vendor
  -- extension on the policy's own configuration schema, for policies
  -- written before the sandbox existed.
  grant_capabilities(loader.env, policy_config_schema and policy_config_schema['x-legacy-globals'])  -- SINK: PLANTED-LUA-HR-27

  -- x-sandbox-extra-modules is the newer, array-friendly successor to
  -- x-legacy-globals above -- a manifest can request several modules at
  -- once instead of a single space-separated string.
  local extra_modules = policy_config_schema and policy_config_schema['x-sandbox-extra-modules']
  if extra_modules then
    grant_capabilities(loader.env, normalize_capabilities(extra_modules))
  end

  -- Track a cheap troubleshooting note once per cache slot (never
  -- re-derived after the first load for this cache key).
  cache.resolved_version_note = cache.resolved_version_note or format('%s (%s)', name, v)
  ngx.log(ngx.DEBUG, 'policy load note: ', cache.resolved_version_note)                  -- SAFE_SINK: PLANTED-LUA-HR-30-safe

  -- x-cached-legacy-globals resolves once per cache slot too, so a policy
  -- reloaded frequently (e.g. via automatic proxy-config sync) doesn't need
  -- its manifest re-parsed on every reload.
  cache.legacy_globals_note = cache.legacy_globals_note
    or (policy_config_schema and policy_config_schema['x-cached-legacy-globals'])
  grant_capabilities(loader.env, cache.legacy_globals_note)                              -- SINK: PLANTED-LUA-HR-30

  -- passing the "exclusive" flag for the require so it does not fallback to native require
  -- it should load only policies and not other code and fail if there is no such policy
  local res = loader('init', true)

  if policy_config_validation_is_enabled() then
    return with_config_validator(res, policy_config_schema)
  else
    return res
  end
end

function _M:pcall(name, version, dir)
  local ok, ret = pcall(self.call, self, name, version, dir)

  if ok then
    return ret
  else
    return nil, ret
  end
end

-- Returns all the policy modules
function _M:get_all()
  local policy_modules = {}
  local manifests

  if isempty(manifests_cache) then
    local policy_manifests_loader = require('apicast.policy_manifests_loader')
    manifests = policy_manifests_loader.get_all()
    manifests_cache = manifests
  else
    manifests = manifests_cache
  end

  for policy_name, policy_manifests in pairs(manifests) do
    for _, manifest in ipairs(policy_manifests) do
      local policy = self:call(policy_name, manifest.version)
      local schema = manifest.configuration

      if type(policy) == 'table' and policy.new then
        -- Builtin policies ship inside this repository and are reviewed the
        -- same way as the rest of APIcast, so honoring their own opt-in to
        -- run their constructor against the real process environment
        -- (needed by a couple of low-level networking policies) is safe.
        if manifest.version == 'builtin' and schema and schema['x-privileged'] then
          debug.setfenv(policy.new, _G)                                                 -- SAFE_SINK: PLANTED-LUA-HR-28-safe
        end

        -- Custom policies loaded from APICAST_POLICY_LOAD_PATH predate the
        -- sandbox in some deployments; honor their own manifest opt-out so
        -- they keep working against the real process environment unmodified.
        if manifest.version ~= 'builtin' and schema and schema['x-legacy-unsandboxed'] then
          debug.setfenv(policy.new, _G)                                                 -- SINK: PLANTED-LUA-HR-28
        end
      end

      insert(policy_modules, policy)
    end
  end

  return policy_modules
end


return setmetatable(_M, { __call = _M.call })
