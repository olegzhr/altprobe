local typedefs = require "kong.db.schema.typedefs"

return {
    name = "custom-log-redis",

    fields = {

        {
            consumer = typedefs.no_consumer
        },

        {
            protocols = typedefs.protocols_http
        },

        {
            config = {

                type = "record",

                fields = {

                    {
                        redis_host = {
                            type = "string",
                            required = true,
                            default = "127.0.0.1",
                        }
                    },

                    {
                        redis_port = {
                            type = "integer",
                            required = true,
                            default = 6379,
                        }
                    },

                    {
                        redis_password = {
                            type = "string",
                            default = "",
                            len_min = 0,
                        }
                    },

                    {
                        redis_database = {
                            type = "integer",
                            default = 0,
                        }
                    },

                    {
                        redis_key = {
                            type = "string",
                            required = true,
                            default = "log_proxy",
                        }
                    },

                    {
                        host_name = {
                            type = "string",
                            default = "localhost",
                        }
                    },

                    {
                        max_body_size = {
                            type = "integer",
                            default = 5000,
                        }
                    },

                    {
                        log_request_body = {
                            type = "boolean",
                            default = true,
                        }
                    },

                    {
                        log_response_body = {
                            type = "boolean",
                            default = true,
                        }
                    },

                    {
                        timeout = {
                            type = "integer",
                            default = 1000,
                        }
                    }
                }
            }
        }
    }
}