# APIcast - Lua SAST benchmark snapshot

Frozen snapshot of an upstream project, republished for Lua static-analysis benchmarking.
**This is not a fork for contribution.** File issues and pull requests upstream.

## Provenance

| | |
|---|---|
| Upstream | <https://github.com/3scale/APIcast> |
| Branch | `master` |
| Commit | `003dafa9c52a8637103565b548cf71408746894a` |
| Snapshot taken | 2026-09-18 |
| Upstream stars at snapshot | 323 |
| Deliberately vulnerable (GOAT) | No |

The tree is byte-identical to upstream at that commit, with two exceptions: the `.git` directory
was removed and replaced by a single `initial version` commit, and this `BENCHMARK.md` was added.
No upstream file was modified, so every line number still matches upstream.

## Corpus metadata

**Project type:** API gateway + management REST API (OpenResty/NGINX, pluggable policy chain)

**Lua version:** 5.1 / LuaJIT 2.1 (OpenResty 1.27.1)

**Frameworks and libraries:** OpenResty/ngx_lua, lua-resty-http, lua-cjson, lua-resty-jwt, lua-resty-env, lua-resty-url, router, penlight, lyaml, liquid, nginx-lua-prometheus, lua-resty-openssl, lua-resty-ipmatcher

**Size class:** Medium (~30347 LOC)

## Taint sources of interest

HTTP headers and cookies (ngx.req.get_headers, ngx.var.http_authorization), HTTP query parameters (ngx.req.get_uri_args), HTTP request body (ngx.req.get_body_data, ngx.req.get_body_file), HTTP path and method (ngx.var.uri, ngx.req.get_method), Outbound HTTP client response (resty.http_ng - 3scale Admin Portal JSON, OIDC discovery), Environment variables (resty.env/os.getenv), Local file read (util.read_file/loadfile)
