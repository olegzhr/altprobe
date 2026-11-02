local typedefs = require "kong.db.schema.typedefs"
return {
  name = "altprobe",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = { type = "record", fields = {
      { redis_host = { type = "string", default = "redis" } },
      { redis_port = { type = "integer", default = 6379, between = {1, 65535} } },
      { redis_key = { type = "string", default = "log_proxy" } },
      { gateway_origin_id = { type = "string", default = "", len_max = 255 } },
      { host_name = { type = "string", default = "kong" } },
      { max_body_size = { type = "integer", default = 5000, between = {1, 32768} } },
      { timeout = { type = "integer", default = 2000, between = {1, 30000} } },
    } } },
  },
}
