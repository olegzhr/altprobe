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

#include "trace_config.h"
#include "cobject.h"
#include <yaml-cpp/yaml.h>
#include <boost/asio/ip/address.hpp>
#include <cstdlib>
#include <sstream>
#include <set>

namespace {
TraceConfig settings;
std::string env(const char* key, const std::string& fallback) {
    const char* value = getenv(key); return value ? value : fallback;
}
int number(const std::string& value) {
    size_t n = 0; int v = std::stoi(value, &n);
    if (n != value.size()) throw std::runtime_error("invalid integer");
    return v;
}
template<class T> T read(const YAML::Node& n, const char* key, T fallback) {
    return n && n[key] ? n[key].as<T>() : fallback;
}
std::vector<std::string> split(const std::string& value) {
    std::vector<std::string> out; std::stringstream stream(value); std::string part;
    while (std::getline(stream, part, ',')) {
        auto first = part.find_first_not_of(" \t"), last = part.find_last_not_of(" \t");
        if (first != std::string::npos) out.push_back(part.substr(first, last-first+1));
    }
    return out;
}
}
const TraceConfig& traceConfig() { return settings; }
bool loadTraceConfig(int mode, std::string& error, const std::string& file) {
    try {
        TraceConfig next;
        next.collector.max_body_bytes = 4194304;
        next.collector.max_requests = 16;
        std::vector<std::string> types{"OCSF","HTTP","OTEL"};
        if (mode == 2) {
            next.mode = env("TRACE_MODE", CObject::trace_enabled ? "internal" : "off");
            next.spool_dir = env("SINKS_TRACE_SPOOL_DIR", next.spool_dir);
            next.max_pending = number(env("SINKS_TRACE_MAX_PENDING", "4096"));
            next.max_spool_bytes = number(env("SINKS_TRACE_MAX_BYTES", "268435456"));
            next.timeout_ms = number(env("SINKS_TRACE_TIMEOUT_MS", "5000"));
            types = split(env("SINKS_OS_TYPES", "OCSF,HTTP,OTEL"));
            auto& c = next.collector;
            c.bind_host = env("SOURCES_OTEL_BIND_HOST", "127.0.0.1");
            next.http_port = number(env("SOURCES_OTEL_HTTP_PORT", "4318"));
            next.grpc_port = number(env("SOURCES_OTEL_GRPC_PORT", "4317"));
            c.workers = number(env("SOURCES_OTEL_WORKERS", "4"));
            c.max_requests = number(env("SOURCES_OTEL_MAX_REQUESTS", "16"));
            c.max_body_bytes = number(env("SOURCES_OTEL_MAX_BODY_BYTES", "4194304"));
            c.request_timeout_ms = number(env("SOURCES_OTEL_REQUEST_TIMEOUT_MS", "5000"));
            c.trusted_peers = split(env("SOURCES_OTEL_TRUSTED_PEERS", "127.0.0.1,::1"));
            c.tls_cert = env("SOURCES_OTEL_TLS_CERT", ""); c.tls_key = env("SOURCES_OTEL_TLS_KEY", "");
            c.tls_ca = env("SOURCES_OTEL_TLS_CA", "");
            next.bearer_token = env("SOURCES_OTEL_BEARER_TOKEN", "");
        } else {
            auto root = YAML::LoadFile(file.empty() ? CONFIG_FILE : file);
            next.mode = read<std::string>(root["altprobe"], "trace_mode", CObject::trace_enabled ? "internal" : "off");
            auto sinks = root["sinks"];
            next.spool_dir = read<std::string>(sinks, "trace_spool_dir", next.spool_dir);
            next.max_pending = read<int>(sinks, "trace_max_pending", next.max_pending);
            next.max_spool_bytes = read<uint64_t>(sinks, "trace_max_bytes", next.max_spool_bytes);
            next.timeout_ms = read<int>(sinks, "trace_timeout_ms", next.timeout_ms);
            if (sinks && sinks["os_types"]) types = sinks["os_types"].as<std::vector<std::string>>();
            auto sources = root["sources"];
            auto n = sources ? sources["otel"] : YAML::Node{}; auto& c = next.collector;
            next.http_port = read<int>(n,"http_port",next.http_port); next.grpc_port = read<int>(n,"grpc_port",next.grpc_port);
            c.bind_host = read<std::string>(n,"bind_host",c.bind_host); c.workers = read<int>(n,"workers",c.workers);
            c.max_requests = read<int>(n,"max_requests",c.max_requests); c.max_body_bytes = read<int>(n,"max_body_bytes",c.max_body_bytes);
            c.request_timeout_ms = read<int>(n,"request_timeout_ms",5000);
            if (n && n["trusted_peers"]) c.trusted_peers = n["trusted_peers"].as<std::vector<std::string>>();
            c.tls_cert = read<std::string>(n,"tls_cert",""); c.tls_key = read<std::string>(n,"tls_key","");
            c.tls_ca = read<std::string>(n,"tls_ca",""); next.bearer_token = read<std::string>(n,"bearer_token","");
        }
        if (next.mode != "internal" && next.mode != "external" && next.mode != "off") throw std::runtime_error("trace_mode must be internal, external or off");
        next.os_ocsf = next.os_http = next.os_otel = false;
        std::set<std::string> unique;
        for (auto type : types) {
            for (char& ch : type) ch = std::toupper(static_cast<unsigned char>(ch));
            if (!unique.insert(type).second) throw std::runtime_error("duplicate os_types entry");
            if (type == "OCSF") next.os_ocsf = true;
            else if (type == "HTTP") next.os_http = true;
            else if (type == "OTEL") next.os_otel = true;
            else throw std::runtime_error("os_types supports OCSF, HTTP and OTEL");
        }
        auto& c = next.collector;
        if (next.spool_dir.empty() || next.spool_dir[0] != '/' || next.max_pending < 1 || next.max_pending > 65536 ||
            next.max_spool_bytes < 1048576 || next.max_spool_bytes > 2147483647 || next.timeout_ms < 100 || next.timeout_ms > 60000 ||
            c.max_body_bytes < 1024 || c.max_body_bytes > 16777216 || c.workers < 1 || c.workers > 32 ||
            c.max_requests < 1 || c.max_requests > 256 || static_cast<uint64_t>(c.max_requests)*c.max_body_bytes > 134217728 || c.request_timeout_ms < 100 || c.request_timeout_ms > 60000 ||
            next.http_port < 0 || next.http_port > 65535 || next.grpc_port < 0 || next.grpc_port > 65535 ||
            (next.http_port && next.http_port == next.grpc_port)) throw std::runtime_error("invalid trace limits/ports");
        boost::asio::ip::make_address(c.bind_host);
        for (auto& peer : c.trusted_peers) peer = boost::asio::ip::make_address(peer).to_string();
        if (next.mode == "external" && ((!next.http_port && !next.grpc_port) || c.trusted_peers.empty())) throw std::runtime_error("external traces require listener and trusted_peers");
        if (c.tls_cert.empty() != c.tls_key.empty() || (!c.tls_ca.empty() && c.tls_cert.empty())) throw std::runtime_error("invalid OTLP TLS settings");
        settings = std::move(next);
        CObject::trace_enabled = settings.mode == "internal";
        return true;
    } catch (const std::exception& e) { error = std::string("[Trace] invalid configuration: ") + e.what(); return false; }
}
