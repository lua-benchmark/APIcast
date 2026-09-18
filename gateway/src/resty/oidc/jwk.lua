local ipairs = ipairs

local tab_new = require('resty.core.base').new_tab
local pkey = require ('resty.openssl.pkey')
local cjson = require ('cjson')

local _M = { }

function _M.convert_keys(res, ...)
    if not res then return nil, ... end
    local keys = tab_new(0, #res.keys)

    for _,jwk in ipairs(res.keys) do
        keys[jwk.kid] = _M.convert_jwk_to_pem(jwk)
    end

    return keys
end

function _M.convert_jwk_to_pem(jwk)
  local val, err = pkey.new(cjson.encode(jwk), { format = "JWK" })
  if not val then
    return nil, err
  end
  jwk.pem = val:tostring("public", "PEM")

  return jwk
end

return _M
