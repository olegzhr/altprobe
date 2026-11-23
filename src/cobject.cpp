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

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <sstream>
#include <cstdlib>
#include <stdexcept>

#include "cobject.h"
#include "trace_config.h"
#include "collector_config.h"
#include "helpers.h"

namespace {

void parseSinkTypes(const std::string& value, bool& ocsf, bool& http_stream, bool& otel) {
    ocsf = http_stream = otel = false;
    std::stringstream stream(value); std::string part;
    while (std::getline(stream, part, ',')) {
        for (char& c : part) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        auto first = part.find_first_not_of(" \t"), last = part.find_last_not_of(" \t");
        if (first == std::string::npos) continue;
        part = part.substr(first, last-first+1);
        if (part == "OCSF") ocsf = true;
        else if (part == "HTTP") http_stream = true;
        else if (part == "OTEL") otel = true;
    }
}

void parseSplunkTypes(const std::string& value) {
    parseSinkTypes(value, CObject::splunk_ocsf, CObject::splunk_http, CObject::splunk_otel);
}

void parseGraylogTypes(const std::string& value) {
    parseSinkTypes(value, CObject::graylog_ocsf, CObject::graylog_http, CObject::graylog_otel);
}

// OpenSearch index names forbid uppercase, spaces and * \ / ? " < > | , # :.
// Normalize project_id into a safe index-name fragment: lowercase, keep
// [a-z0-9_-], turn space/dot/slash into '-', drop other characters, collapse
// and trim '-' separators, and cap the length.
std::string normalizeProjectId(const std::string& raw) {
    std::string mapped;
    mapped.reserve(raw.size());
    for (char c : raw) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')
            mapped.push_back(c);
        else if (c == ' ' || c == '.' || c == '/')
            mapped.push_back('-');
    }
    std::string out;
    out.reserve(mapped.size());
    for (char c : mapped) {
        if (c == '-' && (out.empty() || out.back() == '-')) continue;
        out.push_back(c);
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    if (out.size() > 48) out.resize(48);
    return out;
}

} // namespace

// Initialize static members
bool CObject::cobject_config_flag = false;

// altprobe
string CObject::asset_name = "";
string CObject::host_name = "";
bool CObject::log_debug = false;
int CObject::run_mode = 0;
bool CObject::waf_status = true;
string CObject::api_guard_path = "/etc/altprobe/api_guard.yaml";
string CObject::scoring_weights_path = "/etc/altprobe/scoring_weights.yaml";
string CObject::ruleset_path = "";
string CObject::project_id = "";

// correlator
bool CObject::detection_enabled = false;
int CObject::alias_ttl = 30;
int CObject::alert_cooldown = 30;
int CObject::entity_ttl = 90;
int CObject::cleanup_interval = 100;

// trace
bool CObject::trace_enabled = true;

// Asynchronous Alertflex incident delivery
bool CObject::incident_enabled = false;
string CObject::incident_url = "";
string CObject::incident_spool_dir = "/var/lib/altprobe/incidents";
int CObject::incident_timeout_ms = 5000;
int CObject::incident_max_pending = 512;
bool CObject::incident_allow_http = false;


// sinks
string CObject::af_url = "";
string CObject::logs_rejected_dir = "/var/lib/altprobe/logs-rejected";
bool CObject::af_tls_verify = true;
string CObject::af_tls_ca_file = "";
string CObject::af_key = "";
bool CObject::af_enable = true;

string CObject::os_url = "";
bool CObject::os_tls_verify = true;
string CObject::os_tls_ca_file = "";
string CObject::os_user = "";
string CObject::os_pwd = "";
bool CObject::os_enable = true;
string CObject::splunk_url = "";
string CObject::splunk_token = "";
string CObject::splunk_index = "altprobe";
bool CObject::splunk_ocsf = true;
bool CObject::splunk_http = true;
bool CObject::splunk_otel = true;
bool CObject::splunk_tls_verify = true;
string CObject::splunk_tls_ca_file = "";
bool CObject::splunk_enable = false;

string CObject::graylog_url = "";
bool CObject::graylog_ocsf = true;
bool CObject::graylog_http = true;
bool CObject::graylog_otel = true;
bool CObject::graylog_tls_verify = true;
string CObject::graylog_tls_ca_file = "";
bool CObject::graylog_enable = false;

// sensors
string CObject::redis_host = "";
int CObject::redis_port = 6379;
string CObject::redis_username, CObject::redis_password;
int CObject::redis_database = 0;
string CObject::proxy_log = "";
bool CObject::proxy_log_status = true;

// extra non config parameters
char CObject::sys_log_info[OS_LONG_HEADER_SIZE];
int CObject::gosleep_interval = 1000;

bool CObject::GetConfig(int mode) {
    
    if (!cobject_config_flag) {
        cobject_config_flag = true;
        
        run_mode = mode;
                
        try {
            if (run_mode == 2) {
                // Read from environment variables (environment mode)
                const char* env_val = nullptr;
                
                // Collector parameters
                env_val = getenv("ALTPROBE_LOG_DEBUG");
                log_debug = env_val ? (strcmp(env_val, "true") == 0) : false;
                if (log_debug) printf("altprobe.log_debug: %s", log_debug ? "true\n" : "false\n");
                
                env_val = getenv("ALTPROBE_ASSET_NAME");
                asset_name = env_val ? env_val : "altprobe";
                if (log_debug) printf("altprobe.asset_name: %s\n", (char*) asset_name.c_str());
                
                env_val = getenv("ALTPROBE_HOST_NAME");
                host_name = env_val ? env_val : "altprobe";
                if (log_debug) printf("altprobe.host_name: %s\n", (char*) host_name.c_str());

                env_val = getenv("ALTPROBE_PROJECT_ID");
                {
                    std::string raw = env_val ? env_val : "";
                    project_id = normalizeProjectId(raw);
                    if (project_id != raw)
                        printf("altprobe.project_id: normalized '%s' -> '%s'\n", raw.c_str(), project_id.c_str());
                    else if (log_debug && !project_id.empty())
                        printf("altprobe.project_id: %s\n", (char*) project_id.c_str());
                }
                
                
                env_val = getenv("ALTPROBE_API_GUARD");
                api_guard_path = env_val ? env_val : "/etc/altprobe/api_guard.yaml";
                if (log_debug) printf("altprobe.api_guard: %s\n", (char*) api_guard_path.c_str());

                env_val = getenv("ALTPROBE_SCORING_WEIGHTS");
                scoring_weights_path = env_val ? env_val : "/etc/altprobe/scoring_weights.yaml";
                if (log_debug) printf("altprobe.scoring_weights: %s\n", (char*) scoring_weights_path.c_str());
                
                env_val = getenv("ALTPROBE_RULESET_PATH");
                ruleset_path = env_val ? env_val : "";
                waf_status = !ruleset_path.empty();

                if (log_debug) printf("altprobe.ruleset_path: %s\n", (char*) ruleset_path.c_str());
                
                // Correlator parameters: proxy/API correlation lives under
                // correlator.
                env_val = getenv("CORRELATOR_DETECTION_ENABLED");
                detection_enabled = env_val ? (strcmp(env_val, "true") == 0) : false;
                if (log_debug) printf("correlator.detection_enabled: %s", detection_enabled ? "true\n" : "false\n");

                env_val = getenv("CORRELATOR_ALIAS_TTL");
                if (env_val) alias_ttl = atoi(env_val);
                if (log_debug) printf("correlator.alias_ttl: %d\n", alias_ttl);

                env_val = getenv("CORRELATOR_ALERT_COOLDOWN");
                if (env_val) alert_cooldown = atoi(env_val);
                if (log_debug) printf("correlator.alert_cooldown: %d\n", alert_cooldown);

                env_val = getenv("CORRELATOR_ENTITY_TTL");
                if (env_val) entity_ttl = atoi(env_val);
                if (log_debug) printf("correlator.entity_ttl: %d\n", entity_ttl);

                env_val = getenv("CORRELATOR_CLEANUP_INTERVAL");
                if (env_val) cleanup_interval = atoi(env_val);
                if (log_debug) printf("correlator.cleanup_interval: %d\n", cleanup_interval);

                // Trace parameters
                env_val = getenv("TRACE_ENABLED");
                trace_enabled = env_val ? (strcmp(env_val, "true") == 0) : true;
                if (log_debug) printf("altprobe.trace_enabled: %s", trace_enabled ? "true\n" : "false\n");

                // Sinks parameters
                env_val = getenv("SINKS_AF_URL");
                af_url = env_val ? env_val : "";
                env_val = getenv("SINKS_ALERTFLEX_LOGS_REJECTED_DIR");
                logs_rejected_dir = env_val ? env_val : "/var/lib/altprobe/logs-rejected";
                env_val = getenv("SINKS_AF_TLS_VERIFY");
                if (env_val && strcmp(env_val, "true") != 0 && strcmp(env_val, "false") != 0)
                    throw std::runtime_error("SINKS_AF_TLS_VERIFY must be true or false");
                af_tls_verify = !env_val || strcmp(env_val, "true") == 0;
                env_val = getenv("SINKS_AF_TLS_CA_FILE");
                af_tls_ca_file = env_val ? env_val : "";
                if (log_debug) printf("sinks.af_url: %s\n", (char*) af_url.c_str());
                
                env_val = getenv("SINKS_AF_KEY");
                af_key = env_val ? env_val : "";
                
                if (af_url.empty() || af_key.empty()) af_enable = false;
                if (log_debug) printf("sinks.af_enabled: %s", af_enable ? "true\n" : "false\n");
                
                env_val = getenv("SINKS_OS_URL");
                os_url = env_val ? env_val : "";
                env_val = getenv("SINKS_OS_TLS_VERIFY");
                if (env_val && strcmp(env_val, "true") != 0 && strcmp(env_val, "false") != 0)
                    throw std::runtime_error("SINKS_OS_TLS_VERIFY must be true or false");
                os_tls_verify = !env_val || strcmp(env_val, "true") == 0;
                env_val = getenv("SINKS_OS_TLS_CA_FILE");
                os_tls_ca_file = env_val ? env_val : "";
                if (log_debug) printf("sinks.os_url: %s\n", (char*) os_url.c_str());
                
                env_val = getenv("SINKS_OS_USER");
                os_user = env_val ? env_val : "";
                if (log_debug) printf("sinks.os_user: %s\n", (char*) os_user.c_str());
                
                env_val = getenv("SINKS_OS_PWD");
                os_pwd = env_val ? env_val : "";
                if (log_debug) printf("sinks.os_pwd: %s\n", os_pwd.empty() ? "[not configured]" : "[configured]");
                
                if (os_url.empty() || os_user.empty() || os_pwd.empty())  os_enable = false;
                if (log_debug) printf("sinks.os_enabled: %s", os_enable ? "true\n" : "false\n");

                env_val = getenv("SINKS_SPLUNK_URL");
                splunk_url = env_val ? env_val : "";
                env_val = getenv("SINKS_SPLUNK_TOKEN");
                splunk_token = env_val ? env_val : "";
                env_val = getenv("SINKS_SPLUNK_INDEX");
                splunk_index = (env_val && *env_val) ? env_val : "altprobe";
                env_val = getenv("SINKS_SPLUNK_TYPES");
                parseSplunkTypes(env_val ? env_val : "OCSF,HTTP,OTEL");
                env_val = getenv("SINKS_SPLUNK_TLS_VERIFY");
                if (env_val && strcmp(env_val, "true") != 0 && strcmp(env_val, "false") != 0)
                    throw std::runtime_error("SINKS_SPLUNK_TLS_VERIFY must be true or false");
                splunk_tls_verify = !env_val || strcmp(env_val, "true") == 0;
                env_val = getenv("SINKS_SPLUNK_TLS_CA_FILE");
                splunk_tls_ca_file = env_val ? env_val : "";
                splunk_enable = !splunk_url.empty() && !splunk_token.empty();
                if (log_debug) printf("sinks.splunk_url: %s\n", (char*) splunk_url.c_str());
                if (log_debug) printf("sinks.splunk_enabled: %s", splunk_enable ? "true\n" : "false\n");

                env_val = getenv("SINKS_GRAYLOG_URL");
                graylog_url = env_val ? env_val : "";
                env_val = getenv("SINKS_GRAYLOG_TYPES");
                parseGraylogTypes(env_val ? env_val : "OCSF,HTTP,OTEL");
                env_val = getenv("SINKS_GRAYLOG_TLS_VERIFY");
                if (env_val && strcmp(env_val, "true") != 0 && strcmp(env_val, "false") != 0)
                    throw std::runtime_error("SINKS_GRAYLOG_TLS_VERIFY must be true or false");
                graylog_tls_verify = !env_val || strcmp(env_val, "true") == 0;
                env_val = getenv("SINKS_GRAYLOG_TLS_CA_FILE");
                graylog_tls_ca_file = env_val ? env_val : "";
                graylog_enable = !graylog_url.empty();
                if (log_debug) printf("sinks.graylog_url: %s\n", (char*) graylog_url.c_str());
                if (log_debug) printf("sinks.graylog_enabled: %s", graylog_enable ? "true\n" : "false\n");

                // Sensors parameters
                env_val = getenv("SOURCES_REDIS_HOST");
                redis_host = env_val ? env_val : "";
                if (log_debug) printf("sources.redis_host: %s\n", (char*) redis_host.c_str());
                
                env_val = getenv("SOURCES_REDIS_PORT");
                if (env_val) {
                    char* endptr;
                    long val = strtol(env_val, &endptr, 10);
                    if (*endptr == '\0') redis_port = val;
                }
                if (log_debug) printf("sources.redis_port: %d\n", redis_port);

                env_val = getenv("SOURCES_REDIS_USERNAME");
                redis_username = env_val ? env_val : "";
                env_val = getenv("SOURCES_REDIS_PASSWORD");
                redis_password = env_val ? env_val : "";
                env_val = getenv("SOURCES_REDIS_DATABASE");
                redis_database = 0;
                if (env_val) {
                    char* end;
                    const auto database = strtol(env_val, &end, 10);
                    if (end == env_val || *end || database < 0 || database > 65535)
                        throw std::runtime_error("invalid SOURCES_REDIS_DATABASE");
                    redis_database = static_cast<int>(database);
                }
                
                env_val = getenv("SOURCES_PROXY_LOG");
                proxy_log = env_val ? env_val : "";
                proxy_log_status = !proxy_log.empty();
                if (log_debug) printf("sources.proxy_log: %s\n", (char*) proxy_log.c_str());
                if (log_debug) printf("sources.proxy_log_enabled: %s", proxy_log_status ? "true\n" : "false\n");


            } else {
                // Read from YAML configuration file (system/foreground mode)
                YamlConfig config;
                
                if (!config.isValid()) {
                    SysLog("config error: cannot load configuration file");
                    return false;
                }
                
                // Read altprobe section
                log_debug = config.getBool("altprobe", "log_debug", false);
                if (log_debug) printf("altprobe.log_debug: %s", log_debug ? "true\n" : "false\n");
                
                asset_name = config.getString("altprobe", "asset_name");
                if (asset_name.empty()) asset_name = "altprobe";
                if (log_debug) printf("altprobe.asset_name: %s\n", (char*) asset_name.c_str());
                
                host_name = config.getString("altprobe", "host_name");
                if (host_name.empty()) host_name = "altprobe";
                if (log_debug) printf("altprobe.host_name: %s\n", (char*) host_name.c_str());
                
                
                api_guard_path = config.getString("altprobe", "api_guard");
                if (api_guard_path.empty()) api_guard_path = "/etc/altprobe/api_guard.yaml";
                if (log_debug) printf("altprobe.api_guard: %s\n", (char*) api_guard_path.c_str());

                scoring_weights_path = config.getString("altprobe", "scoring_weights");
                if (scoring_weights_path.empty()) scoring_weights_path = "/etc/altprobe/scoring_weights.yaml";
                if (log_debug) printf("altprobe.scoring_weights: %s\n", (char*) scoring_weights_path.c_str());
                
                ruleset_path = config.getString("altprobe", "ruleset_path");
                waf_status = !ruleset_path.empty();

                {
                    std::string raw = config.getString("altprobe", "project_id");
                    project_id = normalizeProjectId(raw);
                    if (project_id != raw)
                        printf("altprobe.project_id: normalized '%s' -> '%s'\n", raw.c_str(), project_id.c_str());
                    else if (log_debug && !project_id.empty())
                        printf("altprobe.project_id: %s\n", (char*) project_id.c_str());
                }
                if (log_debug) printf("altprobe.ruleset_path: %s\n", (char*) ruleset_path.c_str());
                
                // Read correlator section: proxy/API correlation knobs.
                detection_enabled = config.getBool("correlator", "detection_enabled", false);
                alias_ttl = config.getInt("correlator", "alias_ttl", 30);
                alert_cooldown = config.getInt("correlator", "alert_cooldown", 30);
                entity_ttl = config.getInt("correlator", "entity_ttl", 90);
                cleanup_interval = config.getInt("correlator", "cleanup_interval", 100);
                if (log_debug) {
                    printf("correlator.detection_enabled: %s", detection_enabled ? "true\n" : "false\n");
                    printf("correlator.alias_ttl: %d\n", alias_ttl);
                    printf("correlator.alert_cooldown: %d\n", alert_cooldown);
                    printf("correlator.entity_ttl: %d\n", entity_ttl);
                    printf("correlator.cleanup_interval: %d\n", cleanup_interval);
                }

                // Read trace flag from the main collector section
                trace_enabled = config.getBool("altprobe", "trace_enabled", true);
                if (log_debug) printf("altprobe.trace_enabled: %s", trace_enabled ? "true\n" : "false\n");

                af_url = config.getString("sinks", "af_url");
                logs_rejected_dir = config.getAlertflexString("logs_rejected_dir", "/var/lib/altprobe/logs-rejected");
                af_tls_verify = config.getBoolStrict("sinks", "af_tls_verify", true);
                af_tls_ca_file = config.getString("sinks", "af_tls_ca_file", "");
                if (log_debug) printf("sinks.af_url: %s\n", (char*) af_url.c_str());
                af_key = config.getString("sinks", "af_key");
                if (af_url.empty() || af_key.empty()) af_enable = false;
                if (log_debug) printf("sinks.af_enabled: %s", af_enable ? "true\n" : "false\n");
                
                os_url = config.getString("sinks", "os_url");
                os_tls_verify = config.getBoolStrict("sinks", "os_tls_verify", true);
                os_tls_ca_file = config.getString("sinks", "os_tls_ca_file", "");
                if (log_debug) printf("sinks.os_url: %s\n", (char*) os_url.c_str());
                os_user = config.getString("sinks", "os_user");
                if (log_debug) printf("sinks.os_user: %s\n", (char*) os_user.c_str());
                os_pwd = config.getString("sinks", "os_pwd");
                if (log_debug) printf("sinks.os_pwd: %s\n", os_pwd.empty() ? "[not configured]" : "[configured]");
                if (os_url.empty() || os_user.empty() || os_pwd.empty())  os_enable = false;
                if (log_debug) printf("sinks.os_enabled: %s", os_enable ? "true\n" : "false\n");

                splunk_url = config.getString("sinks", "splunk_url", "");
                splunk_token = config.getString("sinks", "splunk_token", "");
                splunk_index = config.getString("sinks", "splunk_index", "altprobe");
                { auto types = config.getStringList("sinks", "splunk_types", "OCSF,HTTP,OTEL");
                  std::string joined; for (const auto& type : types) { if (!joined.empty()) joined += ","; joined += type; }
                  parseSplunkTypes(joined); }
                splunk_tls_verify = config.getBoolStrict("sinks", "splunk_tls_verify", true);
                splunk_tls_ca_file = config.getString("sinks", "splunk_tls_ca_file", "");
                splunk_enable = !splunk_url.empty() && !splunk_token.empty();
                if (log_debug) printf("sinks.splunk_url: %s\n", (char*) splunk_url.c_str());
                if (log_debug) printf("sinks.splunk_enabled: %s", splunk_enable ? "true\n" : "false\n");

                graylog_url = config.getString("sinks", "graylog_url", "");
                { auto types = config.getStringList("sinks", "graylog_types", "OCSF,HTTP,OTEL");
                  std::string joined; for (const auto& type : types) { if (!joined.empty()) joined += ","; joined += type; }
                  parseGraylogTypes(joined); }
                graylog_tls_verify = config.getBoolStrict("sinks", "graylog_tls_verify", true);
                graylog_tls_ca_file = config.getString("sinks", "graylog_tls_ca_file", "");
                graylog_enable = !graylog_url.empty();
                if (log_debug) printf("sinks.graylog_url: %s\n", (char*) graylog_url.c_str());
                if (log_debug) printf("sinks.graylog_enabled: %s", graylog_enable ? "true\n" : "false\n");

                // Read sensors section
                redis_host = config.getString("sources", "redis_host");
                if (log_debug) printf("sinks.redis_host: %s\n", (char*) redis_host.c_str());
                redis_port = config.getInt("sources", "redis_port", 6379);
                redis_username = config.getString("sources", "redis_username");
                redis_password = config.getString("sources", "redis_password");
                redis_database = config.getIntStrict("sources", "redis_database", 0);
                if (log_debug) printf("sinks.redis_port: %d\n", redis_port);
                
                proxy_log = config.getString("sources", "proxy_log");
                if (log_debug) printf("sources.proxy_log: %s\n", (char*) proxy_log.c_str());


                // Set status flags
                proxy_log_status = !proxy_log.empty();
                if (log_debug) printf("sources.proxy_log_enabled: %s", proxy_log_status ? "true\n" : "false\n");
                
            }
            if (redis_database < 0 || redis_database > 65535 || (!redis_username.empty() && redis_password.empty()))
                throw std::runtime_error("invalid Redis source database or credentials");
        } catch (const std::exception& e) {
            SysLog(const_cast<char*>(e.what()));
            return false;
        } catch (...) {
            SysLog("Unknown error during configuration loading");
            return false;
        }
        
        std::string policy_error;
        if (!loadCollectorSettings(run_mode, policy_error)) { SysLog(const_cast<char*>(policy_error.c_str())); return false; }
        if (!loadTraceConfig(run_mode, policy_error)) { SysLog(const_cast<char*>(policy_error.c_str())); return false; }
    }
    
    return true;
}

void CObject::SysLog(const char* info) {
    if (run_mode > 0) {
        printf("%s\n", info);
    } else {
        // If info equals NULL, function sends sys_log_info variable as string to syslog
        if (info == NULL) daemon_log(LOG_ERR, "%s", sys_log_info);
        else daemon_log(LOG_ERR, "%s", info);
    }
}

