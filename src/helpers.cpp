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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <algorithm>
#include <string>
#include <regex>
#include <cstring>
#include "helpers.h"
#include "cobject.h"

struct ParsedEndpoint {
    std::string host;
    std::string path;
    unsigned int port = 0;
    bool has_scheme = false;
};

static bool startsWith(const std::string& value, const std::string& prefix) {
    return value.compare(0, prefix.size(), prefix) == 0;
}

static ParsedEndpoint parseEndpoint(const std::string& input) {
    ParsedEndpoint out;
    std::string value = lowerCopy(input);
    if (value.empty()) {
        out.path = "/";
        return out;
    }

    size_t authority_start = 0;
    size_t scheme = value.find("://");
    if (scheme != std::string::npos) {
        out.has_scheme = true;
        authority_start = scheme + 3;
    }

    if (!out.has_scheme && value[0] == '/') {
        out.path = value;
        return out;
    }

    size_t path_start = value.find('/', authority_start);
    std::string authority = path_start == std::string::npos
        ? value.substr(authority_start)
        : value.substr(authority_start, path_start - authority_start);
    out.path = path_start == std::string::npos ? "/" : value.substr(path_start);

    size_t at = authority.rfind('@');
    if (at != std::string::npos)
        authority = authority.substr(at + 1);

    if (!authority.empty() && authority[0] == '[') {
        size_t end = authority.find(']');
        out.host = end == std::string::npos ? authority : authority.substr(1, end - 1);
        if (end != std::string::npos && end + 2 <= authority.size() && authority[end + 1] == ':') {
            try { out.port = (unsigned int)std::stoul(authority.substr(end + 2)); }
            catch (...) { out.port = 0; }
        }
        return out;
    }

    size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
        out.host = authority.substr(0, colon);
        try { out.port = (unsigned int)std::stoul(authority.substr(colon + 1)); }
        catch (...) { out.port = 0; }
    } else {
        out.host = authority;
    }

    return out;
}

static bool servicePathMatches(const std::string& raw_path) {
    std::string path = raw_path.empty() ? "/" : lowerCopy(raw_path);
    size_t query = path.find('?');
    if (query != std::string::npos)
        path = path.substr(0, query);

    return path == "/api/v1" ||
           startsWith(path, "/api/v1/") ||
           path == "/logs" ||
           startsWith(path, "/logs/") ||
           path == "/inventory" ||
           startsWith(path, "/inventory/") ||
           path.find("/_bulk") != std::string::npos ||
           path == "/opensearch" ||
           startsWith(path, "/opensearch/");
}

static bool sameCollectorEndpoint(const ParsedEndpoint& dest,
                                  const std::string& configured_url) {
    if (configured_url.empty() || dest.host.empty())
        return false;

    ParsedEndpoint configured = parseEndpoint(configured_url);
    if (configured.host.empty() || dest.host != configured.host)
        return false;

    if (configured.port != 0 && dest.port != 0 && configured.port != dest.port)
        return false;

    return true;
}

static bool matchesConfiguredCollector(const ParsedEndpoint& dest) {
    return sameCollectorEndpoint(dest, CObject::af_url) ||
           sameCollectorEndpoint(dest, CObject::os_url);
}

unsigned int getBufferSize(const char* source) {
    char c;
    unsigned int result = 0;
    while ((c = *source++) != '\0')
        result++;
    return result;
}

bool isValidJSON(const std::string& str) {
    boost::property_tree::ptree pt;
    std::istringstream iss(str);
    try {
        boost::property_tree::read_json(iss, pt);
        return true;
    } catch (const boost::property_tree::json_parser::json_parser_error&) {
        return false;
    }
}

std::string normalizeHexEscapes(const std::string& input) {
    std::string result = input;
    
    // Order matters: longer patterns first
    size_t pos = 0;
    
    // \x5C\x22 -> " (encoded escaped quote)
    while ((pos = result.find("\\x5C\\x22", pos)) != std::string::npos) {
        result.replace(pos, 8, "\"");
        pos += 1;
    }
    
    // \x5C" -> " (backslash before quote)
    pos = 0;
    while ((pos = result.find("\\x5C\"", pos)) != std::string::npos) {
        result.replace(pos, 4, "\"");
        pos += 1;
    }
    
    // \x22 -> " (regular quote)
    pos = 0;
    while ((pos = result.find("\\x22", pos)) != std::string::npos) {
        result.replace(pos, 4, "\"");
        pos += 1;
    }
    
    // \x5C -> \ (backslash)
    pos = 0;
    while ((pos = result.find("\\x5C", pos)) != std::string::npos) {
        result.replace(pos, 4, "\\");
        pos += 1;
    }
    
    return result;
}

std::string fixRawJsonString(const std::string& input) {
    std::string result = normalizeHexEscapes(input);
    
    auto fixField = [&result](const std::string& field_name) {
        // Find field in JSON: "field_name": 
        std::string search_pattern = "\"" + field_name + "\": ";
        size_t field_pos = result.find(search_pattern);
        if (field_pos == std::string::npos) return;
        
        size_t start = field_pos + search_pattern.length();
        if (start >= result.length()) return;
        
        // Check if value is quoted string
        if (result[start] == '"') {
            // Find end of quoted string
            size_t end = start + 1;
            while (end < result.length() && result[end] != '"') {
                if (result[end] == '\\' && end + 1 < result.length()) end++;
                end++;
            }
            if (end < result.length()) end++;
            return; // Already valid quoted string
        }
        
        // NEW: Handle "-" (dash) as null
        if (result.substr(start, 1) == "-") {
            // Check if it's just "-" and not part of a number like "-123"
            size_t end = start + 1;
            while (end < result.length() && (result[end] == ' ' || result[end] == '\t')) end++;
            
            // If next character is comma or closing brace, it's standalone "-"
            if (end < result.length() && (result[end] == ',' || result[end] == '}')) {
                result.replace(start, 1, "null");
            }
            return;
        }
        
        // NEW: Handle empty value (when there's nothing between colon and comma/brace)
        if (result[start] == ',' || result[start] == '}') {
            result.insert(start, "null");
            return;
        }
        
        // Handle raw JSON object or array (starts with '{' or '[')
        if (result[start] == '{' || result[start] == '[') {
            char open_brace = result[start];
            char close_brace = (open_brace == '{') ? '}' : ']';
            int brace_count = 0;
            size_t end = start;
            
            for (; end < result.length(); end++) {
                if (result[end] == open_brace) brace_count++;
                else if (result[end] == close_brace) {
                    brace_count--;
                    if (brace_count == 0) {
                        end++;
                        break;
                    }
                }
            }
            
            if (end <= result.length()) {
                std::string body = result.substr(start, end - start);
                result.replace(start, end - start, "\"" + escapeJsonString(body) + "\"");
            }
        }
    };
    
    // Fix both fields
    fixField("request_body");
    fixField("response_body");
    
    return result;
}

std::string escapeJsonString(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

bool isInternalCollectorDest(const std::string& url) {
    if (url.empty())
        return false;

    ParsedEndpoint parsed = parseEndpoint(url);
    if (!parsed.has_scheme)
        return false;

    return matchesConfiguredCollector(parsed) && servicePathMatches(parsed.path);
}

bool isInternalCollectorDest(const std::string& url,
                             const std::string& dest_host,
                             unsigned int dest_port) {
    if (url.empty())
        return false;

    if (isInternalCollectorDest(url))
        return true;

    ParsedEndpoint dest = parseEndpoint(dest_host);
    if (dest.host.empty())
        dest.host = lowerCopy(dest_host);
    if (dest.port == 0)
        dest.port = dest_port;

    ParsedEndpoint url_endpoint = parseEndpoint(url);
    if (dest.host.empty() && !url_endpoint.host.empty())
        dest = url_endpoint;
    if (dest.host.empty())
        return false;

    std::string path = url_endpoint.path.empty() ? url : url_endpoint.path;

    // Path-only collector routes are internal only when the destination matches
    // a configured Alertflex/OpenSearch endpoint. This keeps collectors from
    // dropping ordinary customer APIs that happen to use /api/v1/.
    return matchesConfiguredCollector(dest) && servicePathMatches(path);
}

bool isValidIp(const std::string& ip) {
    if (ip.empty())
        return false;

    if (ip == "-")
        return false;

    if (ip == "unknown")
        return false;

    if (ip == "localhost")
        return false;

    boost::system::error_code ec;
    boost::asio::ip::make_address(ip, ec);

    return !ec;
}

static int monthFromName(const char* month) {
    static const char* months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    for (int i = 0; i < 12; ++i) {
        if (strncmp(month, months[i], 3) == 0)
            return i + 1;
    }

    return 0;
}

uint64_t parseTimeToMillis(const std::string& iso_time) {
    if (iso_time.empty()) {
        return 0;  // Return 0 for empty string
    }
    
    struct tm tm = {};
    double fractional_seconds = 0.0;
    int tz_hours = 0, tz_minutes = 0;
    char tz_sign = '+';
    int parsed = 0;

    // Nginx/Proxy local time: "24/Oct/2025:23:09:12 +0300"
    char month_name[4] = {};
    int day = 0, year = 0, hour = 0, minute = 0, second = 0;
    parsed = sscanf(iso_time.c_str(),
                    "%d/%3s/%d:%d:%d:%d %c%2d%2d",
                    &day, month_name, &year, &hour, &minute, &second,
                    &tz_sign, &tz_hours, &tz_minutes);

    if (parsed == 9) {
        int month = monthFromName(month_name);
        if (month == 0)
            return 0;

        tm.tm_year = year - 1900;
        tm.tm_mon = month - 1;
        tm.tm_mday = day;
        tm.tm_hour = hour;
        tm.tm_min = minute;
        tm.tm_sec = second;

        time_t epoch_seconds = timegm(&tm);
        int tz_offset_seconds = (tz_hours * 3600 + tz_minutes * 60);
        if (tz_sign == '-')
            tz_offset_seconds = -tz_offset_seconds;

        return ((uint64_t)(epoch_seconds - tz_offset_seconds)) * 1000;
    }

    // ISO timestamp with compact timezone: "2026-06-19T18:06:47.464897+0000"
    parsed = sscanf(iso_time.c_str(),
                    "%d-%d-%dT%d:%d:%lf%c%2d%2d",
                    &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                    &tm.tm_hour, &tm.tm_min, &fractional_seconds,
                    &tz_sign, &tz_hours, &tz_minutes);

    if (parsed == 9) {
        tm.tm_sec = (int)fractional_seconds;
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;

        time_t epoch_seconds = timegm(&tm);
        int tz_offset_seconds = (tz_hours * 3600 + tz_minutes * 60);
        if (tz_sign == '-')
            tz_offset_seconds = -tz_offset_seconds;

        uint64_t milliseconds = (uint64_t)(epoch_seconds - tz_offset_seconds) * 1000;
        double fractional_part = fractional_seconds - (int)fractional_seconds;
        if (fractional_part > 0.0)
            milliseconds += (uint64_t)(fractional_part * 1000.0);

        return milliseconds;
    }
    
    // Try format with fractional seconds: "2026-06-19T18:06:47.464897+0000"
    parsed = sscanf(iso_time.c_str(), 
                    "%d-%d-%dT%d:%d:%lf%c%d:%d",
                    &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                    &tm.tm_hour, &tm.tm_min, &fractional_seconds,
                    &tz_sign, &tz_hours, &tz_minutes);
    // The UTC Z form stops after the timezone character, but seconds have
    // already been parsed. Preserve their integer part as well as milliseconds.
    if (parsed >= 6)
        tm.tm_sec = static_cast<int>(fractional_seconds);
    
    if (parsed < 6) {
        // Try format without fractional seconds: "2026-06-19T18:06:47+0000"
        int sec = 0;
        parsed = sscanf(iso_time.c_str(),
                        "%d-%d-%dT%d:%d:%d%c%d:%d",
                        &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                        &tm.tm_hour, &tm.tm_min, &sec,
                        &tz_sign, &tz_hours, &tz_minutes);
        if (parsed < 6) {
            // Try format with 'Z' timezone: "2026-06-19T18:06:47.464897Z"
            parsed = sscanf(iso_time.c_str(),
                           "%d-%d-%dT%d:%d:%lfZ",
                           &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                           &tm.tm_hour, &tm.tm_min, &fractional_seconds);
            if (parsed < 6) {
                // Try simple format without timezone: "2026-06-19T18:06:47"
                parsed = sscanf(iso_time.c_str(),
                               "%d-%d-%dT%d:%d:%d",
                               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                               &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
                if (parsed < 6) {
                    return 0;  // Parsing failed
                }
                tz_sign = '+';
                tz_hours = 0;
                tz_minutes = 0;
            } else {
                tz_sign = '+';
                tz_hours = 0;
                tz_minutes = 0;
            }
        } else {
            tm.tm_sec = sec;
        }
    }
    
    // Adjust tm fields
    tm.tm_year -= 1900;  // Years since 1900
    tm.tm_mon -= 1;      // Month 0-11
    
    // Convert to Unix timestamp (seconds since epoch)
    // Use timegm (treats input as UTC, ignores timezone)
    time_t epoch_seconds = timegm(&tm);
    
    // Apply timezone offset
    int tz_offset_seconds = (tz_hours * 3600 + tz_minutes * 60);
    if (tz_sign == '-') {
        tz_offset_seconds = -tz_offset_seconds;
    }
    epoch_seconds -= tz_offset_seconds;
    
    // Calculate milliseconds
    uint64_t milliseconds = (uint64_t)epoch_seconds * 1000;
    
    // Add fractional milliseconds if available
    if (fractional_seconds > 0.0) {
        double fractional_part = fractional_seconds - (int)fractional_seconds;
        milliseconds += (uint64_t)(fractional_part * 1000.0);
    }
    
    return milliseconds;
}


bool isApiGuardThreat(const Event& event) {
    return event.guard.kind == "threat" && !event.guard.rule_id.empty() &&
        event.guard.signal == signalName(event.signal);
}

bool isApiGuardActivity(const Event& event) {
    if (isApiGuardThreat(event)) return true;
    if (event.guard.kind != "protocol" || event.guard.rule_id.empty() ||
        event.guard.signal != signalName(event.signal)) return false;
    switch (event.signal) {
        case SIG_A2A_ARTIFACT_EXFIL:
        case SIG_A2A_AUTH_REQUIRED:
        case SIG_A2A_AGENT_CARD_CHANGE:
        case SIG_A2A_UNKNOWN_AGENT:
        case SIG_REST_ENDPOINT_PROBE:
        case SIG_REST_DATA_EXFIL:
            return true;
        default: return false;
    }
}

std::string buildMcpDriftsJson(const std::vector<McpDrift>& drifts) {
    std::string json = "[";
    for (const auto& d : drifts) {
        if (json.size() > 1) json += ',';
        json += "{\"signal\":\"" + escapeJsonString(signalName(d.signal)) +
            "\",\"status\":\"" + escapeJsonString(d.status) +
            "\",\"object_type\":\"" + escapeJsonString(d.object_type) +
            "\",\"object_name\":\"" + escapeJsonString(d.object_name) +
            "\",\"field\":\"" + escapeJsonString(d.field) + "\"}";
    }
    return json + "]";
}

std::string buildApiGuardExplanationJson(const GuardMatch& match) {
    auto quote = [](const std::string& value) { return "\"" + escapeJsonString(value) + "\""; };
    std::string json = "{\"kind\":" + quote(match.kind) + ",\"signal\":" + quote(match.signal) + ",\"rule_id\":" + quote(match.rule_id) +
        ",\"field\":" + quote(match.field) + ",\"reason\":" + quote(match.reason) +
        ",\"ruleset_version\":" + quote(match.ruleset_version) +
        ",\"inspection_status\":" + quote(match.inspection_status) +
        ",\"confidence\":" + std::to_string(match.confidence) + ",\"matched_terms\":[";
    for (size_t i = 0; i < match.matched_terms.size(); ++i) {
        if (i) json += ",";
        json += quote(match.matched_terms[i]);
    }
    return json + "]}";
}

std::string buildLlmGuardExplanationJson(const LlmGuardMatch& m) {
    auto q = [](const std::string& s) { return "\"" + escapeJsonString(s) + "\""; };
    std::string json = "{\"status\":" + q(m.status) + ",\"safety\":" + q(m.safety) +
        ",\"field\":" + q(m.field) + ",\"model\":" + q(m.model) + ",\"provider\":" + q(m.provider) +
        ",\"refusal\":" + q(m.refusal) + ",\"original_size\":" + std::to_string(m.original_size) +
        ",\"duration_ms\":" + std::to_string(m.duration_ms) + ",\"categories\":[";
    for (size_t i = 0; i < m.categories.size(); ++i) { if (i) json += ','; json += q(m.categories[i]); }
    return json + "]}";
}

std::string buildApiGuardActivityJson(const Event& e,
                                      const std::string& uid,
                                      const std::string& source_name,
                                      long logged_time) {
    std::string json;
    std::string signal = signalName(e.signal);
    std::string operation = e.http_method;
    if (!e.url.empty()) {
        if (!operation.empty()) operation += " ";
        operation += e.url;
    }
    if (operation.empty()) operation = signal;

    json.append(e.llm_guard.status.empty() ? "{\"activity_id\":1,\"activity_name\":\"API Guard Detection\"" :
                                            "{\"activity_id\":1,\"activity_name\":\"API Guard Content Assessment\"");
    json.append(",\"category_uid\":6,\"category_name\":\"Application Activity\"");
    json.append(",\"class_uid\":6003,\"class_name\":\"API Activity\",\"action_id\":1");
    json.append(",\"type_uid\":600301");
    if (e.llm_guard.status.empty() || e.llm_guard.status == "checked") json.append(",\"status_id\":1,\"status\":\"Success\"");
    else json.append(",\"status_id\":2,\"status\":\"Failure\"");
    json.append(",\"metadata\":{\"uid\":\"");
    json.append(escapeJsonString(uid));
    json.append("\",\"log_name\":\"");
    json.append(escapeJsonString(source_name));
    json.append("_api_guard\",\"log_provider\":\"Alertflex\",\"logged_time\":");
    json.append(std::to_string(logged_time));
    json.append(",\"correlation_uid\":\"" + escapeJsonString(makeKey(e)) + "\"");
    json.append(",\"version\":\"1.8.0\",\"product\":{\"name\":\"API Guard\",\"vendor_name\":\"Alertflex\"}}");
    if (e.llm_guard.status.empty()) json.append(",\"severity_id\":3,\"severity\":\"High\"");
    else if (isApiGuardThreat(e)) json.append(",\"severity_id\":4,\"severity\":\"High\"");
    else if (e.llm_guard.safety == "Controversial" || e.llm_guard.status != "checked")
        json.append(",\"severity_id\":2,\"severity\":\"Low\"");
    else json.append(",\"severity_id\":1,\"severity\":\"Informational\"");
    json.append(",\"time\":");
    json.append(std::to_string(eventTimeMillis(e.ts, logged_time)));
    json.append(",\"message\":\"");
    json.append(escapeJsonString(signal + " " + e.url));
    json.append("\"");

    json.append(",\"api\":{\"service\":{\"name\":\"");
    json.append(escapeJsonString(source_name));
    json.append("\",\"version\":\"1.0.0\"},\"operation\":\"");
    json.append(escapeJsonString(operation));
    json.append("\"");
    if (e.status > 0) {
        json.append(",\"response\":{\"code\":");
        json.append(std::to_string(e.status));
        json.append("}");
    }
    json.append("}");

    if (e.protocol == "in_process") {
        json.append(",\"actor\":{\"process\":{\"name\":\"");
        json.append(escapeJsonString(e.process));
        json.append("\"}}");
    } else {
        json.append(",\"src_endpoint\":{\"type_id\":99");
        if (!e.host_id.empty()) {
            json.append(",\"hostname\":\"");
            json.append(escapeJsonString(e.host_id));
            json.append("\"");
        }
        json.append(",\"ip\":\"");
        json.append(escapeJsonString(isValidIp(e.src_ip) ? e.src_ip : "0.0.0.0"));
        json.append("\"");
        if (e.src_port > 0) {
            json.append(",\"port\":");
            json.append(std::to_string(e.src_port));
        }
        json.append("}");

        json.append(",\"dst_endpoint\":{\"type_id\":1");
        if (!e.dst_ip.empty()) {
            json.append(",\"name\":\"");
            json.append(escapeJsonString(e.dst_ip));
            json.append("\"");
        }
        json.append(",\"ip\":\"");
        json.append(escapeJsonString(isValidIp(e.dst_ip) ? e.dst_ip : "0.0.0.0"));
        json.append("\"");
        if (e.dst_port > 0) {
            json.append(",\"port\":");
            json.append(std::to_string(e.dst_port));
        }
        json.append("}");

        json.append(",\"http_request\":{\"method\":\"");
        json.append(escapeJsonString(e.http_method));
        json.append("\",\"url\":\"");
        json.append(escapeJsonString(e.url));
        json.append("\",\"user_agent\":\"");
        json.append(escapeJsonString(e.user_agent));
        json.append("\"}");
    }

    json.append(",\"unmapped\":{\"aos\":{\"finding\":{\"title\":\"");
    json.append(escapeJsonString(signal));
    json.append("\",\"uid\":\"");
    json.append(escapeJsonString(uid));
    json.append("\",\"confidence\":");
    json.append(std::to_string(e.guard.rule_id.empty() ? 100 : e.guard.confidence));
    json.append("}");
    json.append(",\"source_event\":{\"provider\":\"api_guard\",\"rule\":\"");
    json.append(escapeJsonString(signal));
    json.append("\"}},\"mcp_drifts\":" + buildMcpDriftsJson(e.mcp_drifts) +
        ",\"mcp_inventory_version\":" + std::to_string(e.policy_inventory_version) +
        ",\"mcp_inventory_status\":\"" + escapeJsonString(e.policy_inventory_status) +
        "\",\"mcp_inventory_inspection_status\":\"" + escapeJsonString(e.policy_inventory_inspection_status) +
        "\",\"api_guard\":" + buildApiGuardExplanationJson(e.guard) +
        (e.llm_guard.status.empty() ? "" : ",\"llm_guard\":" + buildLlmGuardExplanationJson(e.llm_guard)) +
        ",\"observation\":{\"transport\":\"" + escapeJsonString(e.protocol) +
        "\",\"application_protocol\":\"" + escapeJsonString(e.application_protocol) +
        "\",\"operation_id\":\"" + escapeJsonString(e.operation_id) +
        "\",\"operation_state\":\"" + escapeJsonString(e.operation_state) +
        "\",\"operation_status\":" + std::to_string(e.operation_status) +
        ",\"event_time\":" + std::to_string(eventTimeMillis(e.ts, logged_time)) +
        ",\"observed_time\":" + std::to_string(e.observed_ts > 0 ? e.observed_ts : logged_time) +
        ",\"request_original_size\":" + std::to_string(e.request_original_size) +
        ",\"response_original_size\":" + std::to_string(e.response_original_size) +
        ",\"request_truncated\":" + (e.request_truncated ? "true" : "false") +
        ",\"response_truncated\":" + (e.response_truncated ? "true" : "false") +
        ",\"request_missing\":" + (e.request_missing ? "true" : "false") +
        ",\"response_missing\":" + (e.response_missing ? "true" : "false") +
        ",\"request_redacted\":" + (e.request_redacted ? "true" : "false") +
        ",\"response_redacted\":" + (e.response_redacted ? "true" : "false") + "}}");
    json.append("}");

    return json;
}
