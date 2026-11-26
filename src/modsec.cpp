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

#include "proxy.h"
#include "suricata.h"
#include "modsec.h"
#include "helpers.h"
#include "classify.h"

#include <filesystem>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <type_traits>
#include <utility>
namespace fs = std::filesystem;

namespace {
template <typename T, typename = void>
struct RuleIdAccess {
    static int64_t get(const T& rm) { return rm.m_ruleId; }
};

template <typename T>
struct RuleIdAccess<T, std::void_t<decltype(std::declval<const T&>().m_rule.m_ruleId)>> {
    static int64_t get(const T& rm) { return rm.m_rule.m_ruleId; }
};

int64_t ruleIdOf(const modsecurity::RuleMessage* rm) {
    return RuleIdAccess<modsecurity::RuleMessage>::get(*rm);
}
}

Modsec* Modsec::currentInstance = nullptr;

Modsec::Modsec() {
    modsec = make_unique<modsecurity::ModSecurity>();
    rules = make_unique<modsecurity::RulesSet>();
    
    Modsec::currentInstance = this;
    
    modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty
        | modsecurity::IncludeFullHighlightLogProperty);
}

bool Modsec::Open() {
    
    if (waf_status) {
        source_status = loadCRSRules();
    }
    
    return waf_status && source_status;
}

void Modsec::Close() {
    source_status = false;
}

bool Modsec::Go(void) {
    
    
    auto inspect = [&]() {
        processHttpRequest(http.client_ip, http.server_ip, http.server_port,
            http.url, http.http_method, http.version, convertHeaders(http.request_headers), http.request_body);
        http.Reset(); counter++;
    };
    while (q_modsec_proxy.pop(http)) inspect();
    while (q_modsec_suricata.pop(http)) inspect();

    if (counter < 100 && timeout < 10) {
        usleep(GetGosleepInterval()*60);
        timeout++;
    } else {
        counter = 0;
        timeout = 0;
    }
    
    return source_status;
}

void Modsec::logCb(void *, const void *ruleMessagev) {
    
    auto *rm   = static_cast<modsecurity::RuleMessage*>(
        const_cast<void*>(ruleMessagev));

    if (!rm) return;
    
    if (LogProcessingEnabled() || log_debug) currentInstance->createLogRecord(ruleMessagev);
    
    if (detection_enabled)  {
        
        Event e{};

        // ---- timestamp ----
        e.observed_ts = eventTimeMillis(0);
        e.ts = eventTimeMillis(currentInstance->http.event_ts_ms, e.observed_ts);

        const auto& input = currentInstance->http;
        e.host_id = input.identity_host.empty() ? host_name : input.identity_host;
        e.authenticated_gateway = input.authenticated_gateway;
        e.authenticated_principal = input.authenticated_principal;
        e.agent_key = input.agent_key;
        e.session_id = input.session_id;
        e.identity_namespace = input.identity_namespace;
        e.operation_id = input.request_id;
        e.trace_id = input.trace_id;
        e.span_id = input.span_id;
        e.request_missing = input.request_missing;
        e.response_missing = input.response_missing;
        e.request_truncated = input.request_truncated;
        e.response_truncated = input.response_truncated;
        e.request_original_size = input.request_original_size;
        e.response_original_size = input.response_original_size;
     
        // ---- network ----
        e.src_ip = currentInstance->http.client_ip;
        e.dst_ip = currentInstance->http.server_ip;

        e.src_port = 0;
        e.dst_port = currentInstance->http.server_port;

        e.protocol = "http";

        e.http_method = currentInstance->http.http_method;
        e.url = currentInstance->http.url;
        e.user_agent = "";
        e.request_body = currentInstance->http.request_body;
        e.response_body = currentInstance->http.response_body;
        e.status = currentInstance->http.status;

        e.rule = std::to_string(ruleIdOf(rm));
        e.provider = "modsecurity";

        SignalType ruleSignal = currentInstance->mapRuleId(static_cast<int>(ruleIdOf(rm)));
        SignalType bodySignal = classifyHttpMcpSignal(
            e.http_method,
            e.url,
            currentInstance->http.request_headers,
            e.request_body,
            currentInstance->current_request_inspection_ ? "" : e.response_body,
            &e.guard
        );

        e.signal = (ruleSignal != SIG_UNKNOWN) ? ruleSignal : bodySignal;
        // A CRS verdict takes priority; do not attribute it to a different rule.
        if (ruleSignal != SIG_UNKNOWN) e.guard = GuardMatch{};

        e.source = 4;

        if (e.signal != SIG_UNKNOWN)
            enqueueCorrelatorEvent(q_modsec_correlator, e, "modsec");

        if (ruleSignal == SIG_UNKNOWN &&
            (isApiGuardActivity(e) || bodySignal == SIG_PROMPT_INJECTION ||
             bodySignal == SIG_LATERAL_MOVEMENT ||
             bodySignal == SIG_TOOL_ABUSE)) {

            std::string json_api_activity = buildApiGuardActivityJson(
                e, std::to_string(ruleIdOf(rm)), "modsec", e.ts);

            if (log_debug) {
                SysLog((char*)"ModSec API Guard Activity record:");
                SysLog((char*)json_api_activity.c_str());
            }

            currentInstance->sk.sendOcsfToLogSinks(json_api_activity, 6003, "indef", "modsec");
        }
    }
}


bool Modsec::loadCRSRules() {

    string baseConf;

    // --- Core engine ---
    baseConf += "SecRuleEngine On\n";

    // --- Request Response processing ---
    baseConf += "SecRequestBodyAccess On\n";
    baseConf += "SecRequestBodyLimit 13107200\n";
    baseConf += "SecResponseBodyAccess On\n";

    baseConf += "SecResponseBodyMimeType text/plain text/html application/json\n";

    baseConf += "SecResponseBodyLimit 1048576\n";
    baseConf += "SecResponseBodyLimitAction ProcessPartial\n";

    // --- CRS requires persistent storage ---
    baseConf += "SecDataDir /tmp\n";

    // --- Disable logs (test mode) ---
    baseConf += "SecAuditEngine Off\n";
    baseConf += "SecDebugLogLevel 0\n";

    // --- VERY IMPORTANT FOR CRS ---
    baseConf += "SecDefaultAction \"phase:1,log,pass\"\n";
    baseConf += "SecDefaultAction \"phase:2,log,pass\"\n";
    baseConf += "SecDefaultAction \"phase:3,log,pass\"\n";
    baseConf += "SecDefaultAction \"phase:4,log,pass\"\n";

    if (rules->load(baseConf.c_str()) < 0) {
        SysLog("Failed to load base ModSecurity config");
        return false;
    }

    // ---------- CRS setup ----------
    string setupConf = ruleset_path + "/crs-setup.conf";

    if (rules->loadFromUri(setupConf.c_str()) < 0) {
        SysLog("Failed to load crs-setup.conf");
        return false;
    }

    // ---------- Load CRS rules sorted ----------
    string rulesDir = ruleset_path + "/rules";

    try {

        vector<string> files;

        for (auto& p : fs::directory_iterator(rulesDir)) {
            if (p.path().extension() == ".conf") {
                files.push_back(p.path().string());
            }
        }

        sort(files.begin(), files.end());

        for (const auto& file : files) {

            if (rules->loadFromUri(file.c_str()) < 0) {
                SysLog("Failed to load CRS rule file");
                return false;
            }
        }

    }
    catch (...) {
        SysLog("Error reading CRS rules directory");
        return false;
    }
    
    SysLog("CRS loaded successfully");
    
    return true;
}


bool Modsec::processHttpRequest(
    const std::string& clientIP,
    const std::string& serverIP,
    int serverPort,
    const std::string& uri,
    const std::string& method,
    const std::string& httpVersion,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& body)
{    modsecurity::Transaction transaction(
        modsec.get(),
        rules.get(),
        nullptr);

    // Connection
    transaction.processConnection(
        clientIP.c_str(),
        12345,
        serverIP.c_str(),
        serverPort);

    // Normalize HTTP version (remove "HTTP/" prefix)
    std::string version = httpVersion;
    if (version.rfind("HTTP/", 0) == 0) {
        version = version.substr(5);
    }

    // Request
    transaction.processURI(
        uri.c_str(),
        method.c_str(),
        version.c_str());

    bool hasContentType = false;
    bool hasContentLength = false;
    bool isJsonBody = false;
    for (const auto& header : headers) {
        if (header.first == "Content-Type" || header.first == "content-type") {
            hasContentType = true;
            std::string ct = header.second;
            std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
            if (ct.find("application/json") != std::string::npos)
                isJsonBody = true;
        }
        else if (header.first == "Content-Length" || header.first == "content-length")
            hasContentLength = true;
        transaction.addRequestHeader(
            header.first,
            header.second);
    }

    if (!body.empty()) {
        if (!hasContentType) {
            transaction.addRequestHeader("Content-Type", "application/json");
            isJsonBody = true;
        }
        if (!hasContentLength)
            transaction.addRequestHeader("Content-Length", std::to_string(body.size()));
    }

    struct ResetRequestInspection { bool& flag; ~ResetRequestInspection() { flag = false; } } reset{current_request_inspection_};
    current_request_inspection_ = true;
    transaction.processRequestHeaders();

    // libmodsecurity 3.0.6 may not populate ARGS from the URI query string;
    // parse it explicitly (percent-decoded k=v pairs).
    {
        auto urlDecode = [](const std::string& s) {
            std::string out;
            out.reserve(s.size());
            for (size_t i = 0; i < s.size(); i++) {
                if (s[i] == '%' && i + 2 < s.size()) {
                    std::string hex = s.substr(i + 1, 2);
                    char* end = nullptr;
                    long c = std::strtol(hex.c_str(), &end, 16);
                    if (end == hex.c_str() + 2)
                        out.push_back(static_cast<char>(c));
                    else
                        out.push_back(s[i]);
                    i += 2;
                } else if (s[i] == '+') {
                    out.push_back(' ');
                } else {
                    out.push_back(s[i]);
                }
            }
            return out;
        };

        size_t qpos = uri.find('?');
        if (qpos != std::string::npos) {
            std::string query = uri.substr(qpos + 1);
            size_t start = 0;
            while (start < query.size()) {
                size_t amp = query.find('&', start);
                std::string pair = query.substr(start,
                    amp == std::string::npos ? std::string::npos : amp - start);
                size_t eq = pair.find('=');
                std::string k = eq == std::string::npos ? pair : pair.substr(0, eq);
                std::string v = eq == std::string::npos ? "" : pair.substr(eq + 1);
                transaction.addArgument(k, k, urlDecode(v), 0);
                if (amp == std::string::npos) break;
                start = amp + 1;
            }
        }
    }

    if (!body.empty()) {
        // libmodsecurity 3.0.6 JSON body processor may not populate ARGS.
        // Parse the JSON body explicitly (top-level keys as ARGS) so CRS
        // attack rules (942/941/930/932) can match body content.
        if (isJsonBody) {
            try {
                bpt::ptree jpt;
                std::stringstream jss(body);
                bpt::read_json(jss, jpt);
                for (const auto& kv : jpt) {
                    std::string value;
                    if (kv.second.empty())
                        value = kv.second.get_value<std::string>("");
                    else {
                        std::ostringstream oss;
                        bpt::write_json(oss, kv.second, false);
                        value = oss.str();
                    }
                    transaction.addArgument(kv.first, kv.first, value, 0);
                }
            } catch (...) {
            }
        }

        transaction.appendRequestBody(
            reinterpret_cast<const unsigned char*>(body.data()),
            body.size());
    }

    // Always evaluate phase-2 rules (also for GET/query-only requests, where
    // there is no body but ARGS must still be inspected by CRS attack rules).
    transaction.processRequestBody();
    current_request_inspection_ = false;

    // Add response headers (critical for proper ModSecurity processing)
    if (!http.response_body.empty()) {
        transaction.addResponseHeader("Content-Type", "application/json");
        transaction.addResponseHeader("Content-Length", std::to_string(http.response_body.size()));
    }

    // Response headers (phase 3)
    int responseStatus = (http.status > 0) ? http.status : 200;
    transaction.processResponseHeaders(responseStatus, version.c_str());

    // Response body (phase 4)
    if (!http.response_body.empty()) {
        transaction.appendResponseBody(
            reinterpret_cast<const unsigned char*>(http.response_body.data()),
            http.response_body.size());
    }

    // Process response body
    transaction.processResponseBody();

    return hasIntervention(transaction);
}

bool Modsec::hasIntervention(modsecurity::Transaction& transaction) {
    modsecurity::ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = nullptr;
    intervention.log = nullptr;
    intervention.disruptive = 0;
    
    if (transaction.intervention(&intervention)) {
        if (intervention.log) {
            free(intervention.log);
        }
        if (intervention.url) {
            free(intervention.url);
        }
        return true;
    }
    return false;
}

void Modsec::createLogRecord(const void *ruleMessagev) {
    
    auto *rm   = static_cast<modsecurity::RuleMessage*>(
                     const_cast<void*>(ruleMessagev));
    
    try {
        json_report.clear();
        
        json_report.append("{ \"activity_id\": 1 ");
        json_report.append(",\"category_uid\": 2, \"category_name\": \"Findings\"");
        json_report.append(",\"class_uid\": 2004, \"class_name\": \"Detection Finding\", \"action_id\": 2");
        json_report.append(", \"metadata\": { \"uid\": \"");
        json_report.append(rm->m_reference);
        json_report.append("\", \"log_name\":\"modsecurity_log\", \"log_provider\": \"alertflex\", \"logged_time\": ");
        auto now = std::chrono::system_clock::now();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        json_report.append(std::to_string(milliseconds));
        Event identity;
        identity.host_id = http.identity_host.empty() ? host_name : http.identity_host;
        identity.src_ip = http.client_ip;
        identity.authenticated_gateway = http.authenticated_gateway;
        identity.authenticated_principal = http.authenticated_principal;
        json_report.append(",\"correlation_uid\":\"" + escapeJsonString(makeKey(identity)) + "\"");
        json_report.append(", \"version\":\"1.8.0\", \"product\": ");
        json_report.append("{ \"vendor_name\": \"OWASP CRS\" } }");
        json_report.append(", \"finding_info\": { \"title\": \"");
        json_report.append(escapeJsonString(rm->log()));
        json_report.append("\", \"uid\": \"");
        json_report.append(to_string(ruleIdOf(rm)));
        json_report.append("\" }");
            
        switch (rm->m_severity) {
            case 7: json_report.append(", \"severity_id\": 99, \"severity\": \"Informational\"");
                break;
            case 6: json_report.append(", \"severity_id\": 0, \"severity\": \"Informational\"");
                break;
            case 5: json_report.append(", \"severity_id\": 1, \"severity\": \"Informational\"");
                break;
            case 4: json_report.append(", \"severity_id\": 2, \"severity\": \"Low\"");
                break;
            case 3: json_report.append(", \"severity_id\": 3, \"severity\": \"Medium\"");
                break;
            case 2: json_report.append(", \"severity_id\": 4, \"severity\": \"Medium\"");
                break;
            case 1: json_report.append(", \"severity_id\": 5, \"severity\": \"High\"");
                break;
            case 0: json_report.append(", \"severity_id\": 6, \"severity\": \"High\"");
                break;
        }
        
        json_report.append(", \"time\": ");
        json_report.append(std::to_string(milliseconds));
        json_report.append(", \"type_uid\": 200401 }");
        
        if (log_debug) {
            SysLog((char*) "ModSec OCSF Detection Finding record:");
            SysLog((char*) json_report.c_str());
        }
        
        sk.sendOcsfToLogSinks(json_report, 2004, "indef", "modsec");
                
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    } 
}

vector<pair<string, string>> convertHeaders(const string& jsonString) {
    
    vector<pair<string, string>> result;
    
    try {
        // Parsing JSON
        bpt::ptree pt;
        istringstream iss(jsonString);
        bpt::read_json(iss, pt);
        
        // Get headers
        for (const auto& header : pt.get_child("http_headers")) {
            string name = header.second.get<string>("name");
            string value = header.second.get<string>("value");
            result.emplace_back(name, value);
        }
    }
    catch (const std::exception& e) {
        
    }
    
    return result;
}

// =========================================================
// RULE_ID -> SIGNAL mapping (OWASP CRS mappings)
// =========================================================
SignalType Modsec::mapRuleId(int id) {
    // 5001-5112 - Alertflex LLM/MCP response injection and prompt leak rules
    if (id >= 5001 && id <= 5112)
        return SignalType::SIG_PROMPT_INJECTION;

    // 5201-5213 - Alertflex LLM secret exfiltration rules
    if (id >= 5201 && id <= 5213)
        return SignalType::SIG_SECRET_ACCESS;

    // 5301-5313 - Alertflex LLM tool output abuse rules
    if (id >= 5301 && id <= 5313)
        return SignalType::SIG_TOOL_ABUSE;

    // 5401-5413 - Alertflex MCP authz, session, prompt, and sampling abuse rules
    if (id == 5401)
        return SignalType::SIG_MCP_TOOL_CALL;

    if (id >= 5402 && id <= 5404)
        return SignalType::SIG_MCP_TOOL_CALL;

    if (id == 5411)
        return SignalType::SIG_MCP_PROMPT_ACCESS;

    if (id == 5412)
        return SignalType::SIG_MCP_SAMPLING_REQUEST;

    if (id == 5413)
        return SignalType::SIG_MCP_ELICITATION_REQUEST;

    // 5501-5506 - Alertflex REST API abuse rules
    if (id == 5501)
        return SignalType::SIG_REST_SSRF;

    if (id == 5502)
        return SignalType::SIG_REST_DATA_EXFIL;

    if (id == 5503)
        return SignalType::SIG_REST_JWT_ABUSE;

    if (id == 5504)
        return SignalType::SIG_REST_AUTH_BYPASS;

    if (id == 5505)
        return SignalType::SIG_REST_ENDPOINT_PROBE;

    if (id == 5506)
        return SignalType::SIG_REST_RATE_LIMIT_ABUSE;

    // 5601-5608 - Alertflex A2A agent protocol rules
    if (id == 5601)
        return SignalType::SIG_A2A_HTTP;

    if (id == 5602 || id == 5605)
        return SignalType::SIG_A2A_AGENT_CARD_DISCOVERY;

    if (id == 5603)
        return SignalType::SIG_A2A_MESSAGE_SEND;

    if (id == 5604)
        return SignalType::SIG_A2A_TASK_ACCESS;

    if (id == 5606)
        return SignalType::SIG_A2A_PUSH_NOTIFICATION;

    if (id == 5607)
        return SignalType::SIG_A2A_AUTH_REQUIRED;

    if (id == 5608)
        return SignalType::SIG_A2A_ARTIFACT_EXFIL;

    // 920xxx - Protocol / Request Smuggling / Violations
    if (id >= 920000 && id < 921000)
        return SignalType::SIG_PROTOCOL_VIOLATION;

    // 921xxx - Protocol anomalies
    if (id >= 921000 && id < 922000)
        return SignalType::SIG_PROTOCOL_VIOLATION;

    // 930xxx - LFI / Path traversal / RFI / RCE base
    if (id >= 930000 && id < 931000)
        return SignalType::SIG_LFI;

    if (id >= 931000 && id < 932000)
        return SignalType::SIG_RFI;

    if (id >= 932000 && id < 933000)
        return SignalType::SIG_RCE;

    // 941xxx - XSS
    if (id >= 941000 && id < 942000)
        return SignalType::SIG_XSS;

    // 942xxx - SQLi
    if (id >= 942000 && id < 943000)
        return SignalType::SIG_SQLI;

    // 913xxx / 9131xx - scanners / reconnaissance
    if (id >= 913000 && id < 914000)
        return SignalType::SIG_SCANNER;

    // 949xxx - anomaly / final decision layer (WAF score)
    if (id >= 949000 && id < 950000)
        return SignalType::SIG_ANOMALY;

    return SignalType::SIG_UNKNOWN;
}




