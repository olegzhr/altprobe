/*
 *   Copyright 2021-2026 Oleg Zharkov
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

#include "source.h"
#include <string_view>

bool Source::InitializeRedisSession() {
    auto ok = [](void* raw) {
        auto* response = static_cast<redisReply*>(raw);
        if (!response) return false;
        const bool accepted = response->type == REDIS_REPLY_STATUS && response->str &&
            std::string_view(response->str, response->len) == "OK";
        freeReplyObject(response);
        return accepted;
    };
    if (!redis_password.empty()) {
        auto* response = redis_username.empty()
            ? redisCommand(c, "AUTH %b", redis_password.data(), redis_password.size())
            : redisCommand(c, "AUTH %b %b", redis_username.data(), redis_username.size(),
                redis_password.data(), redis_password.size());
        if (!ok(response)) { SysLog("[Redis source] authentication failed"); return false; }
    }
    if (redis_database != 0 && !ok(redisCommand(c, "SELECT %d", redis_database))) {
        SysLog("[Redis source] database selection failed");
        return false;
    }
    return true;
}

// Load configuration for the data source
bool Source::GetConfig(int mode) {
    
    // First, load configuration for output sinks
    if (!CObject::GetConfig(mode)) return false;  // Sink configuration failed
    
    // Redis is usable only when both the endpoint and the per-source key are
    // configured. Keep this endpoint check separate so reading the key below
    // cannot accidentally re-enable Redis with an empty host and later crash
    // redisCommand() with a null redisContext.
    bool redis_endpoint_configured = !redis_host.empty() && redis_port > 0;
    
    if (run_mode == 2) {
        // Environment mode: read configuration from environment variables
        const char* env_val = nullptr;
                
        env_val = getenv(env_key.c_str());
        redis_key = env_val ? env_val : "";
        redis_status = redis_endpoint_configured && !redis_key.empty();
        if (redis_status) redis_key = "lpop " + redis_key;
        
        if (env_key == "SOURCES_PROXY_REDIS" && log_debug) printf("sources.proxy_redis: %s\n", (char*) redis_key.c_str());
    
    } else {
        // Non-environment mode: read configuration from YAML file
        
        YamlConfig config;  // Automatically loads the file
        
        // Get Redis key from configuration
        // Default value "indef" if key is not found
        redis_key = config.getString("sources", config_key);
        redis_status = redis_endpoint_configured && !redis_key.empty();
        if (redis_status) redis_key = "lpop " + redis_key;
        
        if (config_key == "proxy_redis" && log_debug) printf("sources.proxy_redis: %s\n", (char*) redis_key.c_str());
    }
    
    return true;  // Configuration loaded successfully
}

