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

#ifndef COBJECT_H
#define	COBJECT_H

#include "main.h"
#include "config.h"  // Changed to new simple config
#include <atomic>

using namespace std;

class CObject {
public:
    inline static std::atomic<bool> stopping{false};
    static bool cobject_config_flag;
    
    // altprobe
    static string asset_name;
    static string host_name;
    static bool log_debug;
    static int run_mode;
    static bool waf_status;
    inline static bool llm_guard_enabled = false;
    static string api_guard_path;
    static string scoring_weights_path;
    static string ruleset_path;
    // Optional tenant/project identifier. When set, it is appended to the
    // OpenSearch index name after the OCSF class (e.g.
    // ocsf-1.8.0-6003-api_activity-<project_id>-<date>) so existing index
    // templates and dashboards keep matching. Empty = no suffix.
    static string project_id;
    inline static string gateway_type = "apisix";
    
    // correlator
    static bool detection_enabled;
    static int alias_ttl;        // IP alias TTL (seconds)
    static int alert_cooldown;   // Alert cooldown (seconds)
    static int entity_ttl;       // Entity TTL (seconds)
    static int cleanup_interval; // Cleanup interval (events)

    // trace
    static bool trace_enabled;   // collect per-agent chains and match patterns
    
    // Asynchronous Alertflex incident delivery (sinks.alertflex)
    static bool incident_enabled;
    static string incident_url; // defaults to sinks.af_url
    static string incident_spool_dir;
    static int incident_timeout_ms;
    static int incident_max_pending;
    static bool incident_allow_http; // development only
    

    // sinks
    static string af_url;
    static string logs_rejected_dir;
    static bool af_tls_verify;
    static string af_tls_ca_file;
    static string af_key;
    static bool af_enable;
        
    static string os_url;
    static bool os_tls_verify;
    static string os_tls_ca_file;
    static string os_user;
    static string os_pwd;
    static bool os_enable;

    // Splunk HEC sink (OCSF findings and OTLP/JSON traces)
    static string splunk_url;
    static string splunk_token;
    static string splunk_index;
    static bool splunk_ocsf;
    static bool splunk_http;
    static bool splunk_otel;
    static bool splunk_tls_verify;
    static string splunk_tls_ca_file;
    static bool splunk_enable;

    // Graylog GELF HTTP sink (OCSF findings and OTLP/JSON traces)
    static string graylog_url;
    static bool graylog_ocsf;
    static bool graylog_http;
    static bool graylog_otel;
    static bool graylog_tls_verify;
    static string graylog_tls_ca_file;
    static bool graylog_enable;


    // sensors
    static string redis_host;
    static int redis_port;
    static string redis_username, redis_password;
    static int redis_database;
    static string proxy_log;
    static bool proxy_log_status;
        
    // extra non config parameters
    static int gosleep_interval;
    char collector_time[OS_DATETIME_SIZE];
    static char sys_log_info[OS_LONG_HEADER_SIZE];
    
    virtual bool GetConfig(int mode);

    // Unified log-processing gate: build sensor records whenever at least one
    // consumer is active (sinks, correlator or trace). Every sensor must use
    // this predicate instead of its own combination of flags.
    static bool LogProcessingEnabled() {
        return af_enable || os_enable || splunk_enable || graylog_enable ||
               detection_enabled || trace_enabled || llm_guard_enabled;
    }

    int GetGosleepInterval() { return gosleep_interval; }
    static void SysLog(const char* info);
};


#endif	/* COBJECT_H */
