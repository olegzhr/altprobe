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

#include <boost/algorithm/string/replace.hpp>
#include <cmath>
#include <limits>
#include <algorithm>
#include <atomic>
#include "helpers.h"
#include "base64.h"
#include "filter.h"
#include "proxy.h"
#include "suricata.h"
#include "gateway_identity.h"
#include "logs.h"
#include "bounded_json.h"
#include "llm_guard.h"
#include "http_io.h"

boost::lockfree::spsc_queue<Http> q_modsec_proxy{LOGS_QUEUE_SIZE};
boost::lockfree::spsc_queue<string> q_logs_proxy{LOGS_QUEUE_SIZE};
boost::lockfree::spsc_queue<ApiCounterEvent> q_api_counters_proxy{LOGS_QUEUE_SIZE};

static std::string redactAgentKeys(std::string text) {
    size_t pos = 0;
    while ((pos = text.find("afk_", pos)) != std::string::npos) {
        if (pos + 80 <= text.size() && text[pos+36] == '.' &&
                text.substr(pos+4,32).find_first_not_of("0123456789abcdef") == std::string::npos &&
                text.substr(pos+37,43).find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == std::string::npos) {
            text.replace(pos,80,"[REDACTED:agent-key]");
            pos += 20;
        } else pos += 4;
    }
    return text;
}

static unsigned int parseProxyDurationMs(const bpt::ptree& pt) {
    // Proxy logs usually provide duration as a string containing fractional
    // seconds ("0.011"). Some emitters use an integer. Normalize both forms to
    // milliseconds because the OCSF duration field emitted below is numeric and
    // the rest of this module stores it as an unsigned integer.
    std::string raw = pt.get<std::string>("duration", "0");
    if (raw.empty() || raw == "-")
        return 0;

    try {
        double seconds = std::stod(raw);
        if (seconds <= 0.0)
            return 0;
        return static_cast<unsigned int>(std::llround(seconds * 1000.0));
    } catch (const std::exception&) {
        return 0;
    }
}

bool Proxy::Open() {
    
    
    if (proxy_log_status) {
        
        fp = fopen(proxy_log.c_str(), "r");
        if(fp == NULL) {
            SysLog("failed open envoy log file");
            return source_status = false;
        }
        
        fseek(fp,0,SEEK_END);
        stat(proxy_log.c_str(), &buf);    
        file_size = (unsigned long) buf.st_size;
    
    } else {
        
        if (redis_status && !redis_key.empty()) {
            // A transient outage is retried by the owning worker, including
            // when Redis is unavailable at startup.
            redis_retry_at_ = {};
        } else source_status = false;
    }
    
    return source_status;
}

void Proxy::Close() {
    RequestStop();
}

Proxy::~Proxy() { releaseResources(); }

bool Proxy::connectRedis() {
    if (c) { redisFree(c); c = nullptr; }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    try {
        // hiredis bounds connect(), but its hostname lookup is synchronous.
        // Resolve with the existing cancellable, capacity-bounded resolver and
        // pass numeric addresses to hiredis within the same startup deadline.
        auto endpoints = bounded_http::resolve(redis_host, std::to_string(redis_port), deadline,
            [&] { return !source_status.load(); });
        for (const auto& endpoint : endpoints) {
            const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (!source_status || remaining <= 0) break;
            timeval timeout{static_cast<time_t>(remaining / 1000000), static_cast<suseconds_t>(remaining % 1000000)};
            const auto address = endpoint.endpoint().address().to_string();
            c = redisConnectWithTimeout(address.c_str(), redis_port, timeout);
            const timeval io_timeout{0, 250000};
            if (c && !c->err && redisSetTimeout(c, io_timeout) == REDIS_OK && InitializeRedisSession()) return true;
            if (c) redisFree(c);
            c = nullptr;
        }
    } catch (const std::exception&) { /* DNS deadline/stop: retry without exposing endpoint data. */ }
    redis_retry_at_ = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    return false;
}

void Proxy::releaseResources() {
    pending_file_record.clear(); file_record.clear(); discarding_file_record = false;
    
    if (fp != NULL) {
        fclose(fp);
        fp = NULL;
    }
    
    if (reply != NULL) {
        freeReplyObject(reply);
        reply = NULL;
    }
    
    if (c != NULL) {
        redisFree(c);
        c = NULL;
    }
    
    ClearRecords();
    
    redis_status = false;
    source_status = false;
}

void Proxy::IsFileModified() {
    
    int ret = stat(proxy_log.c_str(), &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            pending_file_record.clear(); file_record.clear(); discarding_file_record = false;
            
            if (fp != NULL) fclose(fp);
            fp = fopen(proxy_log.c_str(), "r");
                        
            if (fp == NULL) return;
            else {
                
                fseek(fp,0,SEEK_SET);
                int ret = stat(proxy_log.c_str(), &buf);
                
                if (ret != 0) {
                    fp = NULL;
                    return;
                }
                
                file_size = (unsigned long) buf.st_size;
                return;
            }
        }
        
        file_size = current_size;
        return;
    } 
    
    fp = NULL;
}

int Proxy::ReadFile() {
    if (fp == NULL) IsFileModified();
    if (fp == NULL) return 0;
    file_record.clear();
    // Read at most a bounded amount per poll even if a writer never ends its line.
    size_t consumed = 0;
    while (consumed < MAX_FILE_RECORD_BYTES) {
        if (!fgets(file_payload, OS_PAYLOAD_SIZE, fp)) break;
        const size_t count = std::strlen(file_payload);
        consumed += count;
        const bool complete = count && file_payload[count - 1] == '\n';
        if (!discarding_file_record) {
            if (pending_file_record.size() + count > MAX_FILE_RECORD_BYTES) {
                pending_file_record.clear(); discarding_file_record = true;
                SysLog((char*)"[Proxy] oversized JSON log record discarded (limit 1 MiB)");
            } else pending_file_record.append(file_payload, count);
        }
        if (complete) {
            if (discarding_file_record) {
                discarding_file_record = false;
                continue;
            }
            file_record.swap(pending_file_record);
            ferror_counter = 0;
            return 1;
        }
    }
    ++ferror_counter;
    clearerr(fp);
    if (ferror_counter > EOF_COUNTER) { IsFileModified(); ferror_counter = 0; }
    return 0;
}

bool Proxy::Go(void) {
    if (!source_status) return false;
    
    int res = 0;
    
    ClearRecords();
    
    if (proxy_log_status == 1) {
        
        res = ReadFile();
        
        if (res == -1) {
            SysLog("failed reading envoy events from log");
            usleep(GetGosleepInterval()*60);
            return source_status;
        }
        
        if (res == 0) {
            usleep(GetGosleepInterval()*60);
            return source_status;
        } else res = ParsJson(1);
    
    } else {
    
        if (!c && std::chrono::steady_clock::now() >= redis_retry_at_) connectRedis();
        if (!c) {
            WaitForStop(std::chrono::milliseconds(50));
            return source_status;
        }

        const auto key = redis_key.substr(5); // Source stores "lpop <literal key>".
        reply = static_cast<redisReply*>(redisCommand(c, "LPOP %b", key.data(), key.size()));
        
        if (!reply) {
            redisFree(c); c = nullptr;
            redis_retry_at_ = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            WaitForStop(std::chrono::milliseconds(50));
            return source_status;
        }
    
        if (reply->type == REDIS_REPLY_STRING) {
            res = ParsJson(2);
        } else {
            freeReplyObject(reply);
            reply = NULL;
            usleep(GetGosleepInterval()*60);
            return source_status;
        }
    }
    
    if (res != 0 ) 
        if (LogProcessingEnabled()) CreateLogRecord();
    
    if (redis_status == 1) {
        freeReplyObject(reply);
        reply = NULL;
    }
    
    return source_status;
}

int Proxy::ParsJson (int output_type) {
    
    try {
        ResetStream();

        std::string fixed_json_report;

        if (output_type == 1) {
            
            json_report = file_record.empty() ? std::string(file_payload) : file_record;

            fixed_json_report = fixRawJsonString(redactAgentKeys(json_report));
            
            if (log_debug) {
                SysLog((char*)"Proxy log via file:");
                SysLog((char*) fixed_json_report.c_str());
            }
        
        } else {
            
            json_report.assign(reply->str, getBufferSize(reply->str));
            
            fixed_json_report = fixRawJsonString(redactAgentKeys(json_report));

            if (log_debug) {
                SysLog((char*)"Proxy log via redis:");
                SysLog((char*) fixed_json_report.c_str());
            }
        }
        
        ss << fixed_json_report;
        bpt::read_json(ss, pt);
        
        if (output_type == 1) ctx.host_name = host_name;
        else ctx.host_name = pt.get<string>("host_name", host_name);
        
        ctx.request_uri = pt.get<string>("request_uri", "");
        ctx.request_id = pt.get<string>("request_id", "");
        ctx.gateway_origin_id = pt.get<string>("gateway_origin_id", "");
        ctx.request_method = pt.get<string>("request_method", "");
        ctx.http_version = pt.get<string>("http_version", "");
        ctx.remote_addr = pt.get<string>("remote_addr", "");
        ctx.remote_user = pt.get<string>("remote_user", "");
        ctx.time_local = pt.get<string>("time_local", "");
        ctx.event_ts_ms = pt.get<uint64_t>("timestamp_ms", 0);
        if (!ctx.event_ts_ms) {
            // nginx $msec / ngx.now(): decimal Unix seconds, no float rounding.
            std::string msec = pt.get<std::string>("msec", "");
            try {
                size_t dot = msec.find('.');
                std::string seconds = msec.substr(0, dot);
                std::string fraction = dot == std::string::npos ? "" : msec.substr(dot + 1);
                if (!seconds.empty() && seconds.find_first_not_of("0123456789") == std::string::npos &&
                    fraction.find_first_not_of("0123456789") == std::string::npos) {
                    fraction = (fraction + "000").substr(0, 3);
                    uint64_t sec = std::stoull(seconds);
                    if (sec <= (std::numeric_limits<uint64_t>::max() - 999) / 1000)
                        ctx.event_ts_ms = sec * 1000 + std::stoull(fraction);
                }
            } catch (...) {}
        }
        ctx.server_port = pt.get<int>("server_port", 0);
        ctx.duration = parseProxyDurationMs(pt);
        ctx.status = pt.get<int>("status", 0);
        ctx.body_bytes_sent = pt.get<int>("body_bytes_sent", 0);
        ctx.http_referer = pt.get<string>("http_referer", "");
        ctx.http_host = pt.get<string>("http_host", "");
        ctx.http_user_agent = pt.get<string>("http_user_agent", "");
        ctx.http_accept_language = pt.get<string>("http_accept_language", "");
        ctx.http_accept_encoding = pt.get<string>("http_accept_encoding", "");
        ctx.http_connection = pt.get<string>("http_connection", "");
        ctx.http_cookie = pt.get<string>("http_cookie", "");
        
        
        std::string raw_request_body = pt.get<std::string>("request_body", "{}");
        if (raw_request_body == "-") ctx.request_body = "{}";
        else ctx.request_body = fixRawJsonString(raw_request_body);

        std::string raw_response_body = pt.get<std::string>("response_body", "{}");
        if (raw_response_body == "-") ctx.response_body = "{}";
        else ctx.response_body = fixRawJsonString(raw_response_body);

        ctx.mcp_session_id = pt.get<string>("mcp_session_id", "");
        ctx.mcp_method = pt.get<string>("mcp_method", "");
        ctx.consumer_id = pt.get<string>("consumer_id", "");
        ctx.consumer_name = pt.get<string>("consumer_name", "");

        // The gateway supplies only the authenticated consumer; all client
        // identity headers are ignored. Without a consumer the source IP is
        // the identity fallback.
        ctx.authenticated_gateway = gateway_type;
        if (isObservedGateway(ctx.authenticated_gateway))
            ctx.authenticated_principal = pt.get<string>("authenticated_consumer_name", ctx.consumer_name);
        else if (ctx.authenticated_gateway == "envoy")
            ctx.authenticated_principal = pt.get<string>("authenticated_principal", "");
        // These fields are written by the trusted gateway logger from the
        // inline verifier response, never copied from caller-supplied headers.
        if (pt.get<bool>("agent_key_authenticated", false)) {
            const auto gateway = pt.get<string>("agent_identity_gateway", "");
            const auto principal = pt.get<string>("agent_identity_principal", "");
            if (!authenticatedIdentityKey(gateway, principal).empty()) {
                ctx.authenticated_gateway = gateway;
                ctx.authenticated_principal = principal;
                ctx.agent_key_authenticated = true;
            }
            ctx.identity_name = pt.get<string>("agent_identity_name", "");
            if (ctx.identity_name.empty()) {
                const auto encoded = pt.get<string>("agent_identity_name_b64", "");
                if (!encoded.empty()) {
                    std::string decoded;
                    if (Base64::Decode(encoded, &decoded)) ctx.identity_name = decoded;
                }
            }
        } else {
            // Envoy access logs expose the trusted ext_authz headers directly;
            // presence of a valid gateway/principal pair attests key auth.
            const auto gateway = pt.get<string>("agent_identity_gateway", "");
            const auto principal = pt.get<string>("agent_identity_principal", "");
            if (!authenticatedIdentityKey(gateway, principal).empty() &&
                    gateway != "-" && principal != "-") {
                ctx.authenticated_gateway = gateway;
                ctx.authenticated_principal = principal;
                ctx.agent_key_authenticated = true;
                const auto encoded = pt.get<string>("agent_identity_name_b64", "");
                std::string decoded;
                if (!encoded.empty() && Base64::Decode(encoded, &decoded)) ctx.identity_name = decoded;
            }
        }
        if (authenticatedIdentityKey(ctx.authenticated_gateway, ctx.authenticated_principal).empty()) {
            ctx.authenticated_gateway.clear(); ctx.authenticated_principal.clear();
        }
        
        // Preserve Content-Type and Content-Length from the raw request headers
        // so the ModSecurity transaction reconstruction can pick the right body
        // processor (URLENCODED/JSON) and populate ARGS. Prefer the dedicated
        // fields emitted by the APISIX redis-logger, fall back to req_headers.
        std::string http_content_type = pt.get<std::string>("http_content_type", "");
        std::string http_content_length = pt.get<std::string>("http_content_length", "");
        std::string raw_req_headers = pt.get<std::string>("req_headers", "{}");
        if ((http_content_type.empty() || http_content_length.empty())
                && raw_req_headers != "{}" && raw_req_headers != "-") {
            bpt::ptree hdrs;
            std::stringstream hss(fixRawJsonString(raw_req_headers));
            try {
                bpt::read_json(hss, hdrs);
                if (http_content_type.empty())
                    http_content_type = hdrs.get<std::string>("content-type", "");
                if (http_content_length.empty())
                    http_content_length = hdrs.get<std::string>("content-length", "");
            } catch (...) {
            }
        }
        
        ctx.request_original_size = pt.get<size_t>("request_body_original_size",
            raw_request_body == "-" ? 0 : raw_request_body.size());
        ctx.response_original_size = pt.get<size_t>("response_body_original_size",
            raw_response_body == "-" ? 0 : raw_response_body.size());
        try {
            if (!http_content_length.empty() && http_content_length != "-")
                ctx.request_original_size = std::max(ctx.request_original_size,
                    (size_t)std::stoull(http_content_length));
        } catch (...) {}
        ctx.request_missing = pt.get<bool>("request_body_missing", false) ||
            ((raw_request_body.empty() || raw_request_body == "-" || !pt.get_optional<std::string>("request_body")) &&
             ctx.request_original_size > 0);
        ctx.response_missing = pt.get<bool>("response_body_missing", false) ||
            ((raw_response_body.empty() || raw_response_body == "-") && ctx.response_original_size > 0);
        ctx.request_truncated = pt.get<bool>("request_body_truncated", false) || ctx.request_missing ||
            ctx.request_original_size > raw_request_body.size();
        ctx.response_truncated = pt.get<bool>("response_body_truncated", false) || ctx.response_missing ||
            ctx.response_original_size > raw_response_body.size();

        if (ctx.request_missing || ctx.request_truncated) {
            static std::atomic<uint64_t> incomplete_bodies{0};
            uint64_t total = ++incomplete_bodies;
            if (total == 1 || total % 100 == 0) {
                std::string message = "[Proxy] incomplete request body capture: original_size=" +
                    std::to_string(ctx.request_original_size) + ", captured_size=" +
                    std::to_string(raw_request_body == "-" ? 0 : raw_request_body.size()) +
                    ", total=" + std::to_string(total);
                SysLog((char*)message.c_str());
            }
        }

        ctx.http.client_ip = ctx.remote_addr;
        ctx.http.server_ip = ctx.http_host;
        ctx.http.server_port = ctx.server_port;
        ctx.http.duration = ctx.duration;
        ctx.http.url = ctx.request_uri;
        ctx.http.http_method = ctx.request_method;
        ctx.http.status = ctx.status;
        ctx.http.event_ts_ms = eventTimeMillis(ctx.event_ts_ms ? (long)ctx.event_ts_ms : parseTimeToMillis(ctx.time_local));
        ctx.http.version = ctx.http_version;
        ctx.http.request_body = ctx.request_body;
        ctx.http.response_body = ctx.response_body;
        ctx.http.request_headers = "{\"http_headers\":[";
        bool first_header = true;
        auto appendHeader = [&](const std::string& name, const std::string& value) {
            std::string key = name;
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
            if (!first_header) ctx.http.request_headers.append(",");
            ctx.http.request_headers.append("{\"name\":\"");
            ctx.http.request_headers.append(escapeJsonString(name));
            ctx.http.request_headers.append("\",\"value\":\"");
            ctx.http.request_headers.append(escapeJsonString(key == "authorization" ? "[REDACTED]" : value));
            ctx.http.request_headers.append("\"}");
            first_header = false;
        };

        appendHeader("Host", ctx.http_host);
        appendHeader("Referer", ctx.http_referer);
        appendHeader("Connection", ctx.http_connection);
        if (!http_content_type.empty() && http_content_type != "-") {
            appendHeader("Content-Type", http_content_type);
        }
        if (!http_content_length.empty() && http_content_length != "-") {
            appendHeader("Content-Length", http_content_length);
        }
        appendHeader("User-Agent", ctx.http_user_agent);
        appendHeader("Accept-Language", ctx.http_accept_language);
        appendHeader("Accept-Encoding", ctx.http_accept_encoding);
        appendHeader("Cookie", ctx.http_cookie);

        ctx.http.request_headers.append("],\"http_method\":\"");
        ctx.http.request_headers.append(escapeJsonString(ctx.http.http_method));
        ctx.http.request_headers.append("\",\"url\":\"");
        ctx.http.request_headers.append(escapeJsonString(ctx.http.url));
        ctx.http.request_headers.append("\",\"version\":\"");
        ctx.http.request_headers.append(escapeJsonString(ctx.http.version));
        ctx.http.request_headers.append("\"}");
        
        // Host/:authority and absolute request URIs are client-controlled.
        // A gateway log must not be suppressed as internal collector traffic
        // on that basis. Exclude collector routes explicitly at the gateway.
        
        // send to modsec for check
        ctx.http.request_id = ctx.request_id;
        ctx.http.request_truncated = ctx.request_truncated;
        ctx.http.response_truncated = ctx.response_truncated;
        ctx.http.request_missing = ctx.request_missing;
        ctx.http.response_missing = ctx.response_missing;
        ctx.http.request_original_size = ctx.request_original_size;
        ctx.http.response_original_size = ctx.response_original_size;
        {
            Event identity = buildEventFromProxy(ctx);
            ctx.http.identity_host = identity.host_id;
            ctx.http.agent_key = identity.agent_key; ctx.http.session_id = identity.session_id;
            ctx.http.identity_namespace = identity.identity_namespace;
            ctx.http.authenticated_principal = identity.authenticated_principal;
            ctx.http.authenticated_gateway = identity.authenticated_gateway;
            if (llm_guard_enabled) llmGuard.Submit(ctx.http, "proxy");
        }
        if (waf_status && !q_modsec_proxy.push(ctx.http))
            SysLog((char*)"[Proxy] ModSecurity queue is full; HTTP event was dropped");
        
        ResetStream();
        return 1;
    
    } catch (const exception& ex) {
        SysLog((char*)ex.what());
        ResetStream();
        return 0;
    }
}

void Proxy::CreateLogRecord() {
    try {

        std::string json_full;
        std::string json_light;

        long type_uid = 400200;
        int activity_id = 0;
        std::string activity_name = "Unknown";

        // -------------------- METHOD CLASSIFICATION --------------------
        if (!ctx.http.http_method.empty()) {

            if (ctx.http.http_method == "CONNECT") {
                type_uid = 400201; activity_id = 1; activity_name = "Connect";
            } else if (ctx.http.http_method == "DELETE") {
                type_uid = 400202; activity_id = 2; activity_name = "Delete";
            } else if (ctx.http.http_method == "GET") {
                type_uid = 400203; activity_id = 3; activity_name = "Get";
            } else if (ctx.http.http_method == "HEAD") {
                type_uid = 400204; activity_id = 4; activity_name = "Head";
            } else if (ctx.http.http_method == "OPTIONS") {
                type_uid = 400205; activity_id = 5; activity_name = "Options";
            } else if (ctx.http.http_method == "POST") {
                type_uid = 400206; activity_id = 6; activity_name = "Post";
            } else if (ctx.http.http_method == "PUT") {
                type_uid = 400207; activity_id = 7; activity_name = "Put";
            } else if (ctx.http.http_method == "TRACE") {
                type_uid = 400208; activity_id = 8; activity_name = "Trace";
            } else {
                type_uid = 400299;
                activity_id = 99;
                activity_name = ctx.http.http_method;
            }
        }

        // -------------------- TIMESTAMP --------------------
        auto now = std::chrono::system_clock::now();
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();
        uint64_t event_milliseconds = ctx.event_ts_ms ? ctx.event_ts_ms : parseTimeToMillis(ctx.time_local);
        if (event_milliseconds == 0)
            event_milliseconds = milliseconds;

        // =====================================================
        // FULL (ONLY ALERTFLEX - NO OTHER SINKS)
        // =====================================================
        json_full.append("{\"activity_id\":");
        json_full.append(std::to_string(activity_id));

        json_full.append(",\"activity_name\":\"");
        json_full.append(escapeJsonString(activity_name));

        json_full.append("\",\"category_uid\":4,\"category_name\":\"Network Activity\"");
        json_full.append(",\"class_uid\":4002,\"class_name\":\"HTTP Activity\",\"action_id\":");
        json_full.append(ctx.http.status >= 400 ? "2" : "1");

        json_full.append(",\"dst_endpoint\":{\"ip\":\"");
        
        if (isValidIp(ctx.http.server_ip)) {
            json_full.append(ctx.http.server_ip);
        } else {
            json_full.append("0.0.0.0");
        }
        
        json_full.append("\",\"port\":");
        json_full.append(std::to_string(ctx.http.server_port));
        json_full.append("}");

        json_full.append(",\"duration\":");
        json_full.append(std::to_string(ctx.http.duration));

        json_full.append(",\"http_request\":");
        json_full.append(ctx.http.request_headers);

        if (isValidJSON(ctx.http.request_body) && ctx.http.request_body != "-" && !ctx.http.request_body.empty()) {
            json_full.append(",\"message\": ");
            json_full.append(ctx.http.request_body);
        } else {
            json_full.append(",\"message\": null");
        }
        
        json_full.append(",\"http_response\":{\"code\":");
        json_full.append(std::to_string(ctx.http.status));
        
        if (isValidJSON(ctx.http.response_body) && ctx.http.response_body != "-" && !ctx.http.response_body.empty()) {
            json_full.append(",\"message\": ");
            json_full.append(ctx.http.response_body);
        } else {
            json_full.append(",\"message\": null");
        }
        
        
        // Completeness accompanies full telemetry so the controller can
        // distinguish authoritative lists from truncated or missing captures.
        json_full.append("},\"capture\":{\"request_complete\":");
        json_full.append(!ctx.request_missing && !ctx.request_truncated && isValidJSON(ctx.http.request_body) ? "true" : "false");
        json_full.append(",\"response_complete\":");
        json_full.append(!ctx.response_missing && !ctx.response_truncated && isValidJSON(ctx.http.response_body) ? "true" : "false");
        json_full.append("}, \"metadata\":{\"uid\":\"");
        json_full.append(escapeJsonString(ctx.request_id));
        json_full.append("\",\"log_name\":\"" + sensor_name + "_alertflex\",\"log_provider\":\"Alertflex\",\"logged_time\":");
        json_full.append(std::to_string(milliseconds));
        const std::string auth_key = authenticatedIdentityKey(ctx.authenticated_gateway, ctx.authenticated_principal);
        const std::string identity_metadata = auth_key.empty() ? "" :
            ",\"agent_identity\":{\"gateway\":\"" + escapeJsonString(ctx.authenticated_gateway) +
            "\",\"principal\":\"" + escapeJsonString(ctx.authenticated_principal) +
            "\",\"name\":\"" + escapeJsonString(ctx.identity_name) +
            "\",\"method\":\"" + (ctx.agent_key_authenticated ? "agent_key" : "gateway") + "\"}";
        const std::string consumer_metadata = (ctx.consumer_id.empty() && ctx.consumer_name.empty()) ? "" :
            ",\"consumer_id\":\"" + escapeJsonString(ctx.consumer_id) +
            "\",\"consumer_name\":\"" + escapeJsonString(ctx.consumer_name) + "\"";
        const std::string consumer_agent = ctx.consumer_id.empty() ? "" :
            ",\"agent\":{\"id\":\"" + escapeJsonString(ctx.consumer_id) +
            "\",\"name\":\"" + escapeJsonString(ctx.consumer_name) + "\"}";
        json_full.append(identity_metadata);
        json_full.append(consumer_metadata);
        json_full.append(",\"version\":\"1.8.0\",\"product\":{\"vendor_name\":\"" + sensor_name + "\"}}");
        json_full.append(consumer_agent);

        json_full.append(",\"severity\":\"Informational\",\"severity_id\":1");

        json_full.append(",\"src_endpoint\":{\"ip\":\"");
        
        if (isValidIp(ctx.http.client_ip)) {
            json_full.append(ctx.http.client_ip);
        } else {
            json_full.append("0.0.0.0");
        }
        
        json_full.append("\",\"port\":12345");

        json_full.append("},\"time\":");
        json_full.append(std::to_string(event_milliseconds));

        json_full.append(",\"type_uid\":");
        json_full.append(std::to_string(type_uid));
        json_full.append("}");

        // =====================================================
        // LIGHT (ALL OBSERVABILITY SINKS)
        // =====================================================
        json_light.append("{\"activity_id\":");
        json_light.append(std::to_string(activity_id));

        json_light.append(",\"activity_name\":\"");
        json_light.append(escapeJsonString(activity_name));

        json_light.append("\",\"category_uid\":4,\"category_name\":\"Network Activity\"");
        json_light.append(",\"class_uid\":4002,\"class_name\":\"HTTP Activity\",\"action_id\":");
        json_light.append(ctx.http.status >= 400 ? "2" : "1");

        json_light.append(",\"dst_endpoint\":{\"ip\":\"");
        
        if (isValidIp(ctx.http.server_ip)) {
            json_light.append(ctx.http.server_ip);
        } else {
            json_light.append("0.0.0.0");
        }
        
        json_light.append("\",\"port\":");
        json_light.append(std::to_string(ctx.http.server_port));
        json_light.append("}");

        json_light.append(",\"duration\":");
        json_light.append(std::to_string(ctx.http.duration));

        json_light.append(",\"http_request\":");
        json_light.append(ctx.http.request_headers);

        json_light.append(",\"message\": null, \"http_response\":{\"code\":");
        json_light.append(std::to_string(ctx.http.status));
        
        json_light.append(",\"message\": null}, \"metadata\":{\"uid\":\"");
        json_light.append(escapeJsonString(ctx.request_id));
        json_light.append("\",\"log_name\":\"" + sensor_name + "_alertflex\",\"log_provider\":\"Alertflex\",\"logged_time\":");
        json_light.append(std::to_string(milliseconds));
        json_light.append(identity_metadata);
        json_light.append(consumer_metadata);
        json_light.append(",\"agent_observation_only\":true");
        json_light.append(",\"version\":\"1.8.0\",\"product\":{\"vendor_name\":\"" + sensor_name + "\"}}");
        json_light.append(consumer_agent);

        json_light.append(",\"severity\":\"Informational\",\"severity_id\":1");

        json_light.append(",\"src_endpoint\":{\"ip\":\"");
        
        if (isValidIp(ctx.http.client_ip)) {
            json_light.append(ctx.http.client_ip);
        } else {
            json_light.append("0.0.0.0");
        }
        
        json_light.append("\",\"port\":12345");

        json_light.append("},\"time\":");
        json_light.append(std::to_string(event_milliseconds));

        json_light.append(",\"type_uid\":");
        json_light.append(std::to_string(type_uid));
        json_light.append("}");
        
        // -------------------- DEBUG --------------------
        if (log_debug) {
            SysLog((char*)"Proxy OCSF FULL:");
            SysLog((char*)json_full.c_str());
        }

        // =======================
        // SaaS ingestion control
        // =======================
        
        RequestType req_type = inventory.classifyRequest(
            ctx.http.http_method,
            ctx.http.url,
            ctx.http.request_headers,
            ctx.http.request_body
        );
        
        // Check API endpoint exist in Alertflex
        bool filter_matched = inventory.matchEndpoint(ctx.http, req_type, ep);
        
        // Check MCP is different from inventory
        Event e = buildEventFromProxy(ctx);
        if (req_type == TYPE_MCP && e.mcp_method.empty())
            e.mcp_method = inventory.endpointMethodForRequest(ctx.http, req_type);
        if (req_type == TYPE_A2A && e.a2a_operation.empty())
            e.a2a_operation = inventory.endpointMethodForRequest(ctx.http, req_type);
        inventory.enrich(e);

        bool suppress_alertflex_task = (req_type == TYPE_A2A) &&
            inventory.isA2aTaskActivity(ctx.http, e);
        
        // A2A task changes are too noisy for alertflex-ctrl ingestion for now.
        // Local OpenSearch sink below still receives the event.
        if (req_type != TYPE_UNKNOWN && af_enable && !suppress_alertflex_task) {
            ApiCounterEvent api_counter;
            api_counter.path = inventory.endpointPathForRequest(ctx.http, req_type);
            api_counter.method = inventory.endpointMethodForRequest(ctx.http, req_type);
            api_counter.type = (req_type == TYPE_MCP) ? "MCP" :
                ((req_type == TYPE_A2A) ? "A2A" : "REST");
            api_counter.gateway_origin_id = ctx.gateway_origin_id;
            api_counter.observation_id = ctx.request_id;
            api_counter.last_observed_ms = event_milliseconds;

            // Full API logs and apiCalls are synchronized through separate
            // paths. The full log is sent only when inventory rules require
            // discovery or MCP drift reconciliation, while this compact counter
            // event is emitted for every observed REST/MCP call so alertflex
            // keeps apiCalls and lastObserved current for all statuses.
            bool eligible = !api_counter.gateway_origin_id.empty() && api_counter.gateway_origin_id.size() <= 255 &&
                !api_counter.observation_id.empty() && api_counter.observation_id.size() <= 255;
            if (req_type == TYPE_MCP) {
                Json request;
                eligible = eligible && parseBoundedJson(ctx.http.request_body, request) && request.kind == 'o' &&
                    request.get("id") && request.get("id")->kind != 'n' &&
                    request.string("method").rfind("notifications/", 0) != 0;
            }
            if (eligible) {
                const std::string observation = "\"discovery_observation\":{\"eligible\":true,\"gatewayOriginId\":\"" +
                    escapeJsonString(api_counter.gateway_origin_id) + "\",\"observationId\":\"" +
                    escapeJsonString(api_counter.observation_id) + "\",\"lastObservedMs\":" +
                    std::to_string(event_milliseconds) + "},";
                const auto at = json_full.find("\"metadata\":{");
                if (at != std::string::npos) json_full.insert(at + 12, observation);
                if (!(sensor_source == 2 ? q_api_counters_suricata : q_api_counters_proxy).push(api_counter))
                    SysLog((char*)"[Proxy] Discovery queue full; observation dropped");
            } else if (ctx.gateway_origin_id.empty() || ctx.request_id.empty()) {
                SysLog((char*)"[Proxy] Discovery compatibility error: gateway_origin_id and stable request_id required; request not counted");
            }

            const bool full_log = inventory.shouldSendToAlertflex(req_type, filter_matched, ep, e);
            if ((full_log || !auth_key.empty()) &&
                !(sensor_source == 2 ? q_logs_suricata : q_logs_proxy).push(full_log ? json_full : json_light))
                SysLog((char*)"[Proxy] Alertflex log queue is full; discovery log was dropped");
        }
        
        if (filter_matched) {
            if (ep.logbody == 1) sk.sendOcsfToLogSinks(json_full, 4002, ep.pipeline, sensor_name);
            else sk.sendOcsfToLogSinks(json_light, 4002, ep.pipeline, sensor_name);
        } else sk.sendOcsfToLogSinks(json_light, 4002, "indef", sensor_name);
        
        if (detection_enabled) {
            if (e.signal != SIG_UNKNOWN)
                enqueueCorrelatorEvent(sensor_source == 2 ? q_suricata_correlator : q_proxy_correlator, e, sensor_name.c_str());
        }
        
        // -------------------- API GUARD ACTIVITY (6003) --------------------
        if (!e.mcp_drifts.empty() || isApiGuardActivity(e) || e.signal == SIG_PROMPT_INJECTION ||
            e.signal == SIG_LATERAL_MOVEMENT ||
            e.signal == SIG_TOOL_ABUSE) {

            std::string json_api_activity = buildApiGuardActivityJson(
                e, ctx.request_id, sensor_name, milliseconds);

            if (log_debug) {
                SysLog((char*)"Proxy API Guard Activity record:");
                SysLog((char*)json_api_activity.c_str());
            }

            sk.sendOcsfToLogSinks(json_api_activity, 6003, "indef", sensor_name);
        }

        // -------------------- TRACE (agent chain tracing) --------------------
        // Shared Proxy/Suricata HTTP analysis covers HTTP/MCP/A2A, since all
        // three ride over HTTP in this codebase. Every request becomes a raw
        // TraceEvent; Trace::Go() is what decides whether a chain of events
        // for the same agent matches a configured pattern. Hooked here, AFTER
        // buildEventFromProxy()/inventory.enrich(), so the event already
        // carries the same session/tool identity the correlator sees.
        if (trace_enabled) {
            std::string trace_track = (req_type == TYPE_MCP) ? "MCP" :
                ((req_type == TYPE_A2A) ? "A2A" : "HTTP");

            BodyLimits limits = limitsFor(trace_track, e.url);
            ProcessedBody req = processBody(
                e.request_body, limits.request_max, isValidJSON(e.request_body));
            ProcessedBody resp = processBody(
                e.response_body, limits.response_max, isValidJSON(e.response_body));

            TraceEvent te;
            te.ts              = e.ts;
            te.agent_key       = makeKey(e);
            te.identity_source = te.agent_key.rfind("auth:", 0) == 0
                ? "authenticated_gateway" : "transport_peer";
            te.trust_tier = te.identity_source == "authenticated_gateway"
                ? "authenticated" : "network_observed";
            te.request_missing = ctx.request_missing;
            te.response_missing = ctx.response_missing;
            te.request_id      = truncateField(ctx.request_id, limits.key_max);
            te.session_id      = truncateField(e.session_id, limits.key_max);
            te.host_id         = truncateField(e.host_id, limits.key_max);
            te.track           = trace_track;
            te.src_ip          = e.src_ip;
            te.dst_ip          = e.dst_ip;
            te.dst_port        = e.dst_port;
            te.http_method     = e.http_method;
            te.url             = truncateField(e.url, limits.url_max);
            te.mcp_method      = truncateField(e.mcp_method, limits.mcp_method_max);
            te.user_agent      = truncateField(e.user_agent, limits.ua_max);
            te.request_body    = req.value;
            te.response_body   = resp.value;
            te.status          = e.status;
            te.transport = e.protocol;
            te.application_protocol = e.application_protocol;
            te.operation_state = e.operation_state;
            te.operation_status = e.operation_status;
            te.request_redacted = sanitizeSecrets(e.request_body) != e.request_body;
            te.response_redacted = sanitizeSecrets(e.response_body) != e.response_body;
            te.duration_ms     = ctx.duration;
            te.span_kind       = (req_type == TYPE_MCP) ? "tool" :
                                 ((req_type == TYPE_A2A) ? "a2a" :
                                 ((e.url.find("/v1/messages") != std::string::npos) ? "llm" : "http"));

            te.request_truncated      = req.truncated || ctx.request_truncated;
            te.request_original_size  = std::max(req.original_size, ctx.request_original_size);
            te.response_truncated     = resp.truncated || ctx.response_truncated;
            te.response_original_size = std::max(resp.original_size, ctx.response_original_size);

            enqueueTraceEvent(sensor_source == 2 ? q_suricata_trace : q_proxy_trace, te, sensor_name.c_str());
        }

        ep.Reset();
        
    } catch (const std::exception & ex) {
        SysLog((char*)ex.what());
    }
}

Event Proxy::buildEventFromProxy(const ProxyRecord& ctx) {

    Event e{};

    e.observed_ts = eventTimeMillis(0);
    e.ts = eventTimeMillis(ctx.event_ts_ms ? (long)ctx.event_ts_ms : parseTimeToMillis(ctx.time_local), e.observed_ts);

    // Build the same normalized Event shape used by security-log adapters. The
    // proxy cannot usually identify the local process, but it can provide full
    // HTTP request/response context, which is where MCP JSON-RPC, prompt
    // injection, and tool-abuse payloads are visible.
    // e.host_id = host_name;
    e.host_id = ctx.host_name;
    e.authenticated_gateway = ctx.authenticated_gateway;
    e.authenticated_principal = ctx.authenticated_principal;
    e.identity_name = ctx.identity_name;
    e.consumer_id = ctx.consumer_id;
    e.consumer_name = ctx.consumer_name;
    e.agent_key = authenticatedIdentityKey(e.authenticated_gateway, e.authenticated_principal);
    e.identity_namespace = "gateway";
    e.session_id = isMeaningfulIdentity(ctx.mcp_session_id)
        ? normalizeIdentity(ctx.mcp_session_id) : "";
    e.operation_id = ctx.request_id;
    e.operation_status = ctx.status >= 400 ? 2 : (ctx.status > 0 ? 1 : 0);
    e.request_missing = ctx.request_missing;
    e.response_missing = ctx.response_missing;
    e.request_truncated = ctx.request_truncated;
    e.response_truncated = ctx.response_truncated;
    e.request_original_size = ctx.request_original_size;
    e.response_original_size = ctx.response_original_size;
    e.src_ip = isValidIp(ctx.remote_addr) ? ctx.remote_addr : "";

    e.dst_ip = ctx.http_host;
    e.dst_port = ctx.server_port;
    e.protocol = "http";

    e.http_method = ctx.request_method;
    e.url = ctx.request_uri;
    e.user_agent = ctx.http_user_agent;
    e.request_body = ctx.request_body;
    e.response_body = ctx.response_body;
    e.status = ctx.status;
    e.dsize = (int)(ctx.request_body.size() + ctx.response_body.size());
    e.rule = "proxy_mcp_event";
    e.provider = "proxy";
    e.source = sensor_source;
    if (sensor_source == 2) {
        e.identity_namespace = "network";
        e.src_port = ids_context.src_port;
        e.dst_ip = ids_context.dst_ip;
        e.flow_id = ids_context.flow_id;
        e.network_evidence = "ids_http";
        e.rule = ids_context.rule;
        e.provider = "suricata";
    }
    e.mcp_method = ctx.mcp_method;

    // Reuse the shared HTTP/MCP classifier so Proxy and Modsec produce the
    // same signal for the same body. This avoids source-specific scoring
    // quirks and makes correlation evidence easier to explain.
    e.signal = classifyHttpMcpSignal(
        e.http_method,
        e.url,
        ctx.http.request_headers,
        e.request_body,
        e.response_body,
        &e.guard
    );

    if (sensor_source == 2 && ids_context.signal != SIG_UNKNOWN && e.guard.kind != "threat") {
        if (e.signal != ids_context.signal) e.guard = GuardMatch{};
        e.signal = ids_context.signal;
    }
    if (e.signal == SIG_UNKNOWN && isLLMProviderIndicator(ctx.http_host))
        e.signal = SIG_AI_PROVIDER_USAGE;
    
    normalizeEvent(e);
    return e;
}

void Proxy::ProcessIdsHttp(const Http& http, const Event& context) {
    ClearRecords();
    sensor_name = "suricata"; sensor_source = 2; ids_context = context;
    ctx.host_name = context.host_id; ctx.http = http;
    ctx.gateway_origin_id = context.operation_id.empty() ? "" : "suricata:" + context.host_id;
    ctx.request_id = "eve:" + context.host_id + ":" + context.operation_id;
    ctx.event_ts_ms = context.ts;
    ctx.request_uri = http.url; ctx.request_method = http.http_method;
    ctx.http_version = http.version; ctx.remote_addr = http.client_ip;
    ctx.http_host = context.sni.empty() ? http.server_ip : context.sni;
    ctx.server_port = http.server_port; ctx.duration = http.duration; ctx.status = http.status;
    ctx.http_user_agent = context.user_agent;
    ctx.request_body = http.request_body; ctx.response_body = http.response_body;
    ctx.request_missing = http.request_missing; ctx.response_missing = http.response_missing;
    ctx.request_truncated = http.request_truncated; ctx.response_truncated = http.response_truncated;
    ctx.request_original_size = http.request_original_size; ctx.response_original_size = http.response_original_size;
    ctx.http.request_id = ctx.request_id;
    if (llm_guard_enabled) llmGuard.Submit(ctx.http, sensor_name);
    if (waf_status && !q_modsec_suricata.push(ctx.http)) SysLog((char*)"[Suricata] ModSecurity queue full");
    CreateLogRecord();
}
