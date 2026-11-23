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

#include "http_io.h"
#include "tls_client.h"
/*
 *   Copyright 2021 Oleg Zharkov
 */

#include "sinks.h"
#include "base64.h"
#include "helpers.h"
#include "trace_config.h"
#include "json_wire.h"

#include <algorithm>
#include <cctype>

namespace {

// Enforce the collector's project at the top level without ambiguous keys.
std::string withProjectId(const std::string& json, const std::string& project) {
    if (project.empty()) return json;
    Json document;
    if (!parseBoundedJson(json, document, 32 * 1024 * 1024, 1048576) || document.kind != 'o')
        throw std::runtime_error("invalid OCSF document");
    auto field = [](Json& object, const std::string& key) -> Json& {
        for (auto& child : object.children) if (child.first == key) return child.second;
        return object.children.emplace_back(key, Json{}).second;
    };
    auto& metadata = field(document, "metadata");
    if (metadata.kind == 'n') metadata.kind = 'o';
    if (metadata.kind != 'o') throw std::runtime_error("invalid OCSF metadata");
    field(metadata, "project_id") = Json{'s', project};
    return wireJson(document);
}

// GELF 1.1 document for Graylog's GELF HTTP input. The structured OCSF or
// OTLP/JSON record is carried verbatim in full_message, so Graylog keeps the
// exact sensor bytes; a few additional _fields make the record searchable and
// let a Graylog pipeline route or parse it without changing the payload.
std::string gelfDocument(const std::string& event_json, const std::string& short_message,
                         const std::string& stream, int ocsf_type,
                         const std::string& source, const std::string& pipeline) {
    const std::string host = !CObject::host_name.empty() ? CObject::host_name
        : (!CObject::project_id.empty() ? CObject::project_id
        : (!CObject::asset_name.empty() ? CObject::asset_name : "altprobe"));
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::ostringstream out;
    out << "{\"version\":\"1.1\""
        << ",\"host\":\"" << escapeJsonString(host) << "\""
        << ",\"short_message\":\"" << escapeJsonString(short_message) << "\""
        << ",\"full_message\":\"" << escapeJsonString(event_json) << "\""
        << ",\"timestamp\":" << std::fixed << std::setprecision(3)
        << (static_cast<double>(millis) / 1000.0)
        << ",\"level\":6"
        << ",\"_stream\":\"" << escapeJsonString(stream) << "\""
        << ",\"_altprobe_source\":\"" << escapeJsonString(source) << "\"";
    if (ocsf_type > 0) out << ",\"_ocsf_class_uid\":" << ocsf_type;
    if (!CObject::project_id.empty() && CObject::project_id != host)
        out << ",\"_project_id\":\"" << escapeJsonString(CObject::project_id) << "\"";
    if (!pipeline.empty() && pipeline != "indef")
        out << ",\"_pipeline\":\"" << escapeJsonString(pipeline) << "\"";
    out << "}";
    return out.str();
}

} // namespace

Sinks::Sinks() = default;


// -------------------- DATE --------------------
std::string Sinks::getDateIndex(const std::string& index) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d");
    if (project_id.empty())
        return index + oss.str();
    // Multi-tenancy: append the project after the OCSF class so the index
    // templates (ocsf-1.8.0-<class>*) and the lab dashboards keep matching.
    return index + "-" + project_id + "-" + oss.str();
}

// -------------------- HTTP CORE --------------------

bool Sinks::sendHttpRequest(
    bool is_https,
    const std::string& host,
    const std::string& port_str,
    const std::string& target,
    const std::string& method,
    const std::string& body,
    const std::string& auth_header,
    const std::map<std::string, std::string>& extra_headers,
    const std::string& content_type,
    bool tls_verify, const std::string& tls_ca_file, unsigned* status,
    std::function<bool()> stop, std::chrono::milliseconds timeout
) {
    try {
        // The shared client bounds every network stage and observes daemon stop.
        const auto result = bounded_http::request(is_https, host, port_str, target,
            method, body, auth_header, extra_headers, content_type,
            timeout, std::move(stop), 8 * 1024 * 1024, tls_verify, tls_ca_file);
        if (status) *status = result.result_int();
        if (result.result() == http::status::ok || result.result() == http::status::created ||
                result.result() == http::status::accepted ||
                result.result() == http::status::no_content) return true;
        SysLog((char*)("[Sinks] HTTP error: " + std::to_string(result.result_int())).c_str());
        return false;
    } catch (const std::exception& error) {
        SysLog((char*)("[Sinks] HTTP exception: " + std::string(error.what())).c_str());
        return false;
    }
}

// -------------------- LOG SINKS --------------------

int Sinks::sendOcsfToLogSinks(const std::string& log, int ocsf_type, const std::string& pipeline) {
    return sendOcsfToLogSinks(log, ocsf_type, pipeline, "sensor");
}

int Sinks::sendOcsfToLogSinks(const std::string& log, int ocsf_type, const std::string& pipeline, const std::string& source) {
    if (source == "openshell") SysLog((char*)("[Sinks] openshell class=" + std::to_string(ocsf_type) + " os=" + (os_enable ? "1" : "0")).c_str());

    if (ocsf_type != 0 && ocsf_type != 1007 && ocsf_type != 2002 && ocsf_type != 2004 &&
        ocsf_type != 3002 && ocsf_type != 4001 && ocsf_type != 4002 && ocsf_type != 4005 &&
        ocsf_type != 4007 && ocsf_type != 5019 && ocsf_type != 6002 && ocsf_type != 6003) return 1;

    int splunk_result = 1;
    if (splunk_enable) splunk_result = sendOcsfToSplunk(log, ocsf_type);
    int graylog_result = 1;
    if (graylog_enable) graylog_result = sendOcsfToGraylog(log, ocsf_type, pipeline, source);
    const int external_result = std::min(splunk_result, graylog_result);

    if (!os_enable) return external_result;
    if (ocsf_type == 4002 ? !traceConfig().os_http : !traceConfig().os_ocsf) return external_result;

    try {
        const std::string payload = withProjectId(log, project_id);
        bool is_https = (os_url.find("https://") == 0);

        std::string url = os_url;
        if (url.find("http://") == 0) url = url.substr(7);
        else if (url.find("https://") == 0) url = url.substr(8);

        size_t slash = url.find('/');
        std::string host_part = (slash != std::string::npos) ? url.substr(0, slash) : url;
        std::string target = (slash != std::string::npos) ? url.substr(slash) : "/";

        std::string host, port_str;

        size_t colon = host_part.find(':');
        if (colon != std::string::npos) {
            host = host_part.substr(0, colon);
            port_str = host_part.substr(colon + 1);
        } else {
            host = host_part;
            port_str = is_https ? "443" : "9200";
        }

        std::string index;
        if (source == "openshell") {
            if (ocsf_type == 0) index = getDateIndex("ocsf-1.8.0-0-base_event");
            else if (ocsf_type == 1007) index = getDateIndex("ocsf-1.8.0-1007-process_activity");
            else if (ocsf_type == 2004) index = getDateIndex("ocsf-1.8.0-2004-detection_finding");
            else if (ocsf_type == 3002) index = getDateIndex("ocsf-1.8.0-3002-authentication");
            else if (ocsf_type == 4001) index = getDateIndex("ocsf-1.8.0-4001-network_activity");
            else if (ocsf_type == 4002) index = getDateIndex("ocsf-1.8.0-4002-http_activity");
            else if (ocsf_type == 4007) index = getDateIndex("ocsf-1.8.0-4007-ssh_activity");
            else if (ocsf_type == 5019) index = getDateIndex("ocsf-1.8.0-5019-device_config_state_change");
            else if (ocsf_type == 6002) index = getDateIndex("ocsf-1.8.0-6002-application_lifecycle");
            else index = getDateIndex("ocsf-1.8.0-6003-api_activity");
        } else if (ocsf_type == 0) index = getDateIndex("ocsf-1.8.0-0-base_event");
        else if (ocsf_type == 1007) index = getDateIndex("ocsf-1.8.0-1007-process_activity");
        else if (ocsf_type == 2002) index = getDateIndex("ocsf-1.8.0-2002-vulnerability_finding");
        else if (ocsf_type == 2004) index = getDateIndex("ocsf-1.8.0-2004-detection_finding");
        else if (ocsf_type == 3002) index = getDateIndex("ocsf-1.8.0-3002-authentication");
        else if (ocsf_type == 4001) index = getDateIndex("ocsf-1.8.0-4001-network_activity");
        else if (ocsf_type == 4005) index = getDateIndex("ocsf-1.8.0-4005-network_activity");
        else if (ocsf_type == 4007) index = getDateIndex("ocsf-1.8.0-4007-ssh_activity");
        else if (ocsf_type == 5019) index = getDateIndex("ocsf-1.8.0-5019-device_config_state_change");
        else if (ocsf_type == 6002) index = getDateIndex("ocsf-1.8.0-6002-application_lifecycle");
        else if (ocsf_type == 6003) index = getDateIndex("ocsf-1.8.0-6003-api_activity");
        else if (ocsf_type == 0) index = getDateIndex("ocsf-1.8.0-0-base_event");
        else if (ocsf_type == 1007) index = getDateIndex("ocsf-1.8.0-1007-process_activity");
        else if (ocsf_type == 3002) index = getDateIndex("ocsf-1.8.0-3002-authentication");
        else if (ocsf_type == 5019) index = getDateIndex("ocsf-1.8.0-5019-device_config_state_change");
        else if (ocsf_type == 6002) index = getDateIndex("ocsf-1.8.0-6002-application_lifecycle");
        else index = getDateIndex("ocsf-1.8.0-4002-http_activity");

        if (target.empty() || target.back() != '/') target += "/";
        target += index + "/_doc";

        // Adding a pipeline for HTTP activities (ocsf_type == 4002)
        if (ocsf_type == 4002 && pipeline != "indef" && !pipeline.empty()) {
            target += "?pipeline=" + pipeline;
        }

        std::string creds = os_user + ":" + os_pwd;
        std::string enc;
        if (!Base64::Encode(creds, &enc)) return 0;

        std::string auth = "Basic " + enc;
        
        if (log_debug) SysLog((char*) "Sent to OpenSearch");

        int os_result = sendHttpRequest(
            is_https, host, port_str, target,
            "POST", payload, auth,
            {}, "application/json", os_tls_verify, os_tls_ca_file
        ) ? 1 : 0;

        if (source == "openshell") SysLog((char*)("[Sinks] openshell index=" + index + " result=" + std::to_string(os_result)).c_str());
        return std::min(os_result, external_result);

    } catch (std::exception const& e) {
        SysLog((char*)e.what());
        return 0;
    }
}

namespace {
// Parse an HTTP(S) sink URL. Missing path defaults to "/", missing port to the
// sink-specific scheme default.
bool splitSinkUrl(const std::string& url, bool& https, std::string& host,
                  std::string& port, std::string& target,
                  const std::string& https_port, const std::string& http_port) {
    https = url.rfind("https://", 0) == 0;
    if (!https && url.rfind("http://", 0) != 0) return false;
    std::string rest = url.substr(https ? 8 : 7);
    auto slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    target = slash == std::string::npos ? "/" : rest.substr(slash);
    if (authority.empty()) return false;
    port = https ? https_port : http_port;
    auto colon = authority.rfind(':');
    if (colon != std::string::npos) { host = authority.substr(0, colon); port = authority.substr(colon + 1); }
    else host = authority;
    return !host.empty() && !port.empty();
}

bool splitSplunkUrl(const std::string& url, bool& https, std::string& host, std::string& port, std::string& target) {
    return splitSinkUrl(url, https, host, port, target, "443", "8088");
}
}

int Sinks::sendOcsfToSplunk(const std::string& log, int ocsf_type) {
    if (!splunk_enable || log.empty()) return 1;
    if (ocsf_type == 4002 ? !splunk_http : !splunk_ocsf) return 1;
    try {
        bool https = false; std::string host, port, target;
        if (!splitSplunkUrl(splunk_url, https, host, port, target)) {
            SysLog((char*) "[Splunk] invalid HEC URL"); return 0;
        }
        const std::string body = "{\"time\":" + std::to_string(std::time(nullptr)) +
            ",\"host\":\"" + (project_id.empty() ? std::string("altprobe") : project_id) +
            "\",\"source\":\"altprobe\",\"sourcetype\":\"ocsf\",\"index\":\"" + splunk_index +
            "\",\"event\":" + log + "}";
        return sendHttpRequest(https, host, port, target, "POST", body,
            "Splunk " + splunk_token, {}, "application/json", splunk_tls_verify, splunk_tls_ca_file) ? 1 : 0;
    } catch (const std::exception& e) { SysLog((char*) ("[Splunk] " + std::string(e.what())).c_str()); return 0; }
}

int Sinks::sendTraceToSplunk(const std::string& log, unsigned* status, std::function<bool()> stop) {
    if (!splunk_enable || !splunk_otel || log.empty()) return 1;
    try {
        bool https = false; std::string host, port, target;
        if (!splitSplunkUrl(splunk_url, https, host, port, target)) {
            SysLog((char*) "[Splunk] invalid HEC URL"); return 0;
        }
        const std::string body = "{\"time\":" + std::to_string(std::time(nullptr)) +
            ",\"host\":\"" + (project_id.empty() ? std::string("altprobe") : project_id) +
            "\",\"source\":\"altprobe\",\"sourcetype\":\"otel:trace\",\"index\":\"" + splunk_index +
            "\",\"event\":" + log + "}";
        return sendHttpRequest(https, host, port, target, "POST", body,
            "Splunk " + splunk_token, {}, "application/json", splunk_tls_verify, splunk_tls_ca_file,
            status, std::move(stop), std::chrono::milliseconds(traceConfig().timeout_ms)) ? 1 : 0;
    } catch (const std::exception& e) { SysLog((char*) ("[Splunk] " + std::string(e.what())).c_str()); return 0; }
}

// Graylog GELF HTTP input: POST /gelf with one GELF 1.1 document per event.
// The sensor JSON stays byte-identical inside full_message; Graylog itself is
// expected to extract or route it with a pipeline rule.
int Sinks::sendOcsfToGraylog(const std::string& log, int ocsf_type,
                             const std::string& pipeline, const std::string& source) {
    if (!graylog_enable || log.empty()) return 1;
    if (ocsf_type == 4002 ? !graylog_http : !graylog_ocsf) return 1;
    try {
        bool https = false; std::string host, port, target;
        if (!splitSinkUrl(graylog_url, https, host, port, target, "443", "12201")) {
            SysLog((char*) "[Graylog] invalid GELF URL"); return 0;
        }
        if (target.empty() || target == "/") target = "/gelf";
        const std::string body = gelfDocument(log, "altprobe ocsf " + std::to_string(ocsf_type),
            "ocsf", ocsf_type, source, pipeline);
        return sendHttpRequest(https, host, port, target, "POST", body, {}, {},
            "application/json", graylog_tls_verify, graylog_tls_ca_file) ? 1 : 0;
    } catch (const std::exception& e) { SysLog((char*) ("[Graylog] " + std::string(e.what())).c_str()); return 0; }
}

int Sinks::sendTraceToGraylog(const std::string& log, unsigned* status, std::function<bool()> stop) {
    if (!graylog_enable || !graylog_otel || log.empty()) return 1;
    try {
        bool https = false; std::string host, port, target;
        if (!splitSinkUrl(graylog_url, https, host, port, target, "443", "12201")) {
            SysLog((char*) "[Graylog] invalid GELF URL"); return 0;
        }
        if (target.empty() || target == "/") target = "/gelf";
        const std::string body = gelfDocument(log, "altprobe otel trace", "otel", 0, "trace", "");
        return sendHttpRequest(https, host, port, target, "POST", body, {}, {},
            "application/json", graylog_tls_verify, graylog_tls_ca_file, status,
            std::move(stop), std::chrono::milliseconds(traceConfig().timeout_ms)) ? 1 : 0;
    } catch (const std::exception& e) { SysLog((char*) ("[Graylog] " + std::string(e.what())).c_str()); return 0; }
}

