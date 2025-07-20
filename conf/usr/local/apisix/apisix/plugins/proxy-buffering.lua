-- /plugins/proxy-buffering.lua
local plugin = {
  version = 0.1,
  priority = 7999,          -- run after proxy-rewrite (8000)
  name = "proxy-buffering",
  schema = {
    type = "object",
    properties = {
      disable_proxy_buffering = { type = "boolean" }
    },
    required = { "disable_proxy_buffering" }
  }
}

function plugin.header_filter(conf, ctx)
  if conf.disable_proxy_buffering then
    ngx.ctx.proxy_disable_buffering = true
  end
end

return plugin