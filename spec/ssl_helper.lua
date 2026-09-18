local ffi = require "ffi"
local C = ffi.C

ffi.cdef([[
  typedef long time_t;
  typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
  typedef struct x509_store_st X509_STORE;
  X509_VERIFY_PARAM *X509_STORE_get0_param(X509_STORE *ctx);
  void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
]])

local SSL = {}

function SSL.set_time(store, seconds)
  local verify_param = C.X509_STORE_get0_param(store)
  C.X509_VERIFY_PARAM_set_time(verify_param, seconds)
end

return SSL
