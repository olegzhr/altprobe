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

#include "collector_config.h"
#include "cobject.h"
#include "gateway_identity.h"
#include <yaml-cpp/yaml.h>
#include <cstdlib>
#include <stdexcept>

namespace {
std::string environment(const char* key, const char* fallback) {
    const auto value = std::getenv(key);
    return value ? value : fallback;
}
bool boolean(const std::string& text) {
    if (text == "true") return true;
    if (text == "false") return false;
    throw std::runtime_error("expected true/false in collector settings");
}
int integer(const std::string& text) {
    size_t end = 0;
    const int value = std::stoi(text, &end);
    if (end != text.size()) throw std::runtime_error("invalid collector integer");
    return value;
}
template<class T> T setting(const YAML::Node& node, const char* key, T fallback) {
    return node && node[key] ? node[key].as<T>() : fallback;
}
}

bool loadCollectorSettings(int mode, std::string& error, const std::string& file) {
    try {
        std::string gateway = "apisix", url, spool = "/var/lib/altprobe/incidents";
        bool enabled = false, allow_http = false, legacy_policy = false;
        int timeout = 5000, capacity = 512;
        if (mode == 2) {
            gateway = environment("ALTPROBE_GATEWAY_TYPE", "apisix");
            enabled = boolean(environment("SINKS_ALERTFLEX_INCIDENT_ENABLED", "false"));
            allow_http = boolean(environment("SINKS_ALERTFLEX_ALLOW_HTTP", "false"));
            url = environment("SINKS_ALERTFLEX_URL", "");
            spool = environment("SINKS_ALERTFLEX_SPOOL_DIR", "/var/lib/altprobe/incidents");
            timeout = integer(environment("SINKS_ALERTFLEX_TIMEOUT_MS", "5000"));
            capacity = integer(environment("SINKS_ALERTFLEX_MAX_PENDING", "512"));
            legacy_policy = boolean(environment("POLICY_ENABLED", "false"));
        } else {
            const auto root = YAML::LoadFile(file.empty() ? CONFIG_FILE : file);
            gateway = setting<std::string>(root["altprobe"], "gateway_type", "apisix");
            const auto sink = root["sinks"]["alertflex"];
            enabled = setting<bool>(sink, "incident_enabled", false);
            allow_http = setting<bool>(sink, "allow_http", false);
            url = setting<std::string>(sink, "url", "");
            spool = setting<std::string>(sink, "spool_dir", "/var/lib/altprobe/incidents");
            timeout = setting<int>(sink, "timeout_ms", 5000);
            capacity = setting<int>(sink, "max_pending", 512);
            legacy_policy = setting<bool>(root["policy"], "enabled", false);
        }
        if (legacy_policy) throw std::runtime_error("authorization moved to ctrlprobe; remove policy.enabled/POLICY_ENABLED from collector");
        if (!isObservedGateway(gateway)) throw std::runtime_error("invalid collector gateway_type");
        if (timeout < 100 || timeout > 60000 || capacity < 1 || capacity > 100000 || spool.empty())
            throw std::runtime_error("invalid collector incident delivery limits");
        CObject::gateway_type = gateway;
        CObject::incident_enabled = enabled;
        CObject::incident_allow_http = allow_http;
        CObject::incident_url = url;
        CObject::incident_spool_dir = spool;
        CObject::incident_timeout_ms = timeout;
        CObject::incident_max_pending = capacity;
        return true;
    } catch (const std::exception&) {
        // Do not echo configuration values or credentials in diagnostics.
        error = "Invalid collector settings: check gateway_type / sink limits; authorization belongs to ctrlprobe";
        return false;
    }
}
