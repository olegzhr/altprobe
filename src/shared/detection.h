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

#ifndef DETECTION_H
#define DETECTION_H

#include <string>
#include <unordered_map>
#include <vector>
#include <deque>
#include <cstdint>

// ==============================
// 1. SIGNAL MODEL
// ==============================
//
// Unified signal abstraction layer.
// Signal values are stable; API Guard and policy telemetry emit them.
//

enum SignalType {

    SIG_UNKNOWN = 0,

    // ---- Runtime signals (retained for API Guard compatibility) ----
    SIG_MCP_IPC,           // unix socket / pipe communication
    SIG_PROC_SPAWN_AI,     // python/node/java agent spawn
    SIG_PROC_NET_CLIENT,   // outbound connection
    SIG_PROC_BEHAVIOR,     // tool invocation / agent behavior
    SIG_MCP_STDIO,         // MCP JSON-RPC observed directly on process stdin/stdout

    // ---- Network signals (retained for API Guard compatibility) ----
    SIG_TLS_JA3_AI,        // JA3 fingerprint (AI clients)
    SIG_SMALL_TLS_REQ,     // small TLS request loop
    SIG_TLS_BURST,         // connection burst
    SIG_LONG_TLS_SESSION,
    SIG_REPETITIVE_TLS_PATTERN,
    SIG_ANOMALY_BEHAVIOR,  // fallback anomaly
    SIG_HTTP_PATTERN,      // HTTP API / tool pattern
            
    // ==============================
    // LLM signals
    // ==============================

    SIG_TLS_SNI_LLM,
    SIG_DNS_LLM,
    SIG_TLS_CERT_LLM,
    SIG_ASN_LLM,

    // ---- Attack-chain / API protocol signals ----
    //
    // These signals are higher-level than raw IDS signatures. They describe
    // attacker intent or API protocol stages so the correlator can build a
    // multi-stage attack story instead of scoring isolated events only.
    SIG_MCP_HTTP,
    SIG_MCP_TOOL_LIST,
    SIG_MCP_TOOL_CALL,
    SIG_MCP_RESOURCE_ACCESS,
    SIG_PROMPT_INJECTION,
    SIG_TOOL_ABUSE,
    SIG_LATERAL_MOVEMENT,
    SIG_SECRET_ACCESS,
    SIG_AI_PROVIDER_USAGE,
    SIG_AI_GATEWAY_CONTEXT,
    SIG_CORPORATE_DATA_CONTEXT,
    SIG_MCP_CHAIN_STAGE,
    SIG_ATTACK_PIPELINE,
    SIG_MCP_INVENTORY_DISCOVERY,
    SIG_MCP_INVENTORY_CHANGE,
    SIG_MCP_UNKNOWN_TOOL,
    SIG_MCP_UNKNOWN_RESOURCE,
    SIG_MCP_UNKNOWN_PROMPT,
    SIG_MCP_ENDPOINT_DRIFT,
    SIG_MCP_PROMPT_ACCESS,
    SIG_MCP_SAMPLING_REQUEST,
    SIG_MCP_ELICITATION_REQUEST,

    // ---- A2A / Agent2Agent protocol signals ----
    SIG_A2A_HTTP,
    SIG_A2A_AGENT_CARD_DISCOVERY,
    SIG_A2A_AGENT_CARD_CHANGE,
    SIG_A2A_MESSAGE_SEND,
    SIG_A2A_TASK_ACCESS,
    SIG_A2A_TASK_CANCEL,
    SIG_A2A_PUSH_NOTIFICATION,
    SIG_A2A_ARTIFACT_EXFIL,
    SIG_A2A_AUTH_REQUIRED,
    SIG_A2A_UNKNOWN_AGENT,

    // ---- REST API signals ----
    SIG_REST_API_CALL,
    SIG_REST_AUTH_BYPASS,
    SIG_REST_DATA_EXFIL,
    SIG_REST_RATE_LIMIT_ABUSE,
    SIG_REST_ENDPOINT_PROBE,
    SIG_REST_SSRF,
    SIG_REST_JWT_ABUSE,
    SIG_USER_FRAUD_CONTEXT,
    
    // =========================
    // OWASP CRS - Web Attacks
    // =========================

    // SQL Injection
    SIG_SQLI,

    // XSS
    SIG_XSS,

    // RCE
    SIG_RCE,

    // Path traversal / LFI / RFI
    SIG_PATH_TRAVERSAL,
    SIG_LFI,
    SIG_RFI,

    // Protocol violations
    SIG_PROTOCOL_VIOLATION,

    // Scanner / reconnaissance
    SIG_SCANNER,

    // generic anomaly fallback
    SIG_ANOMALY,
    SIG_SHADOW_API // observed endpoint absent from managed API inventory
};

enum ChainStage {
    CHAIN_STAGE_UNKNOWN = 0,
    CHAIN_STAGE_RUNTIME,
    CHAIN_STAGE_LLM,
    CHAIN_STAGE_MCP,
    CHAIN_STAGE_PROMPT,
    CHAIN_STAGE_TOOL,
    CHAIN_STAGE_SHELL,
    CHAIN_STAGE_NETWORK,
    CHAIN_STAGE_LATERAL,
    CHAIN_STAGE_DATA,
    CHAIN_STAGE_REST_API,
    CHAIN_STAGE_A2A
};

// ==============================
// 2. EVENT MODEL
// ==============================
//
// Unified event passed into correlation engine.
// All sources MUST normalize into this structure.
//

struct GuardMatch {
    std::string kind; // threat, context or protocol; distinct from confidence.
    std::string signal;
    std::string rule_id;
    std::string field;
    std::string reason;
    std::string ruleset_version;
    std::string inspection_status;
    int confidence = 0; // Rule confidence, not proof that an attack succeeded.
    std::vector<std::string> matched_terms; // Configured terms, never payload excerpts.
};

struct McpDrift {
    SignalType signal = SIG_UNKNOWN;
    std::string status;
    std::string object_type;
    std::string object_name;
    std::string field; // Changed field only; no observed schema/description contents.
};

struct LlmGuardMatch {
    std::string status, safety, field, model, provider;
    std::string refusal = "Unknown";
    std::vector<std::string> categories;
    size_t original_size = 0;
    long duration_ms = 0;
};

struct Event {
    LlmGuardMatch llm_guard;
    GuardMatch guard;

    long ts = 0; // event time (milliseconds)
    long observed_ts = 0; // ingestion time, independent of event time
    std::string authenticated_principal; // Only gateway-authenticated log fields, never request headers.
    std::string authenticated_gateway;
    std::string identity_name; // Human-readable agent name; display only, never an identity key.
    std::string agent_key; // resolved identity shared with tracing
    std::string identity_namespace; // separates client/gateway/local identities
    std::string operation_id;
    std::string operation_state = "completed";
    std::string application_protocol;
    int operation_status = 0; // 0 unknown, 1 success, 2 error
    bool request_truncated = false;
    bool response_truncated = false;
    bool request_missing = false;
    bool response_missing = false;
    bool request_redacted = false;
    bool response_redacted = false;
    size_t request_original_size = 0;
    size_t response_original_size = 0;

    // ---- Identity layer (CRITICAL for correlation) ----
    std::string host_id;
    std::string consumer_id;   // Alertflex agents.rec_id (id/consumerId)
    std::string consumer_name; // Alertflex agents.client_name (display only)
    std::string container_id, container_name, pod_id, pod_name, k8s_namespace;
    std::string network_evidence, flow_id;

    // Logical request/session identity for MCP/A2A and other non-IP transports.
    // Do not overload src_ip with session ids.
    std::string session_id;
    std::string trace_id;
    std::string span_id;

    // ---- Process / user context ----
    std::string process;
    std::string user;

    // ---- Network context ----
    std::string src_ip;
    std::string dst_ip;

    int src_port = 0;
    int dst_port = 0;

    std::string protocol;

    // ---- HTTP / API context ----
    //
    // Proxy and ModSecurity can both provide full HTTP bodies. Keeping these
    // fields inside Event lets the same body classifier detect MCP JSON-RPC,
    // REST API abuse, prompt injection, tool abuse, and provider usage.
    std::string http_method;
    std::string url;
    std::string user_agent;
    std::string request_body;
    std::string response_body;
    int status = 0;

    // Inventory enrichment populates these fields for MCP JSON-RPC endpoints
    // discovered over HTTP (tools/resources/prompts). Keeping them in the
    // common Event model lets the classifier and correlator tag evidence with
    // MCP object metadata alongside Proxy and Modsec signals.
    int process_pid = 0;
    std::string process_pid_scope; // host / container; empty means unproven

    std::string mcp_method;
    std::string mcp_object_type;
    std::string mcp_object_name;
    std::string policy_inventory_status;
    uint64_t policy_inventory_version = 0;
    std::vector<McpDrift> mcp_drifts;
    std::string policy_inventory_inspection_status;

    // A2A enrichment mirrors MCP metadata for agent-to-agent traffic.
    std::string a2a_operation;
    std::string a2a_agent_name;
    std::string a2a_skill_id;
    std::string a2a_task_id;
    std::string a2a_task_state;

    // ---- Signal type ----
    SignalType signal = SIG_UNKNOWN;

    // ---- TLS enrichment ----
    std::string ja3;
    std::string sni;
    int tls_version = 0;

    // ---- Network metrics ----
    int dsize = 0; // payload size
    int freq = 0;  // request frequency (optional)

    // ---- Source / evidence ----
    //
    // rule/provider/file_path/command are optional evidence fields. They keep
    // source-specific context near the normalized signal without forcing the
    // correlator to parse the original sensor format.
    std::string rule;
    std::string provider;
    std::string file_path;
    std::string command;

    int source = 0; // 1 = runtime, 2 = network, 3 = Proxy, 4 = Modsec, 5 = coding agent
};

struct Evidence {
    LlmGuardMatch llm_guard;
    GuardMatch guard;
    long ts = 0;
    int source = 0;
    SignalType signal = SIG_UNKNOWN;
    ChainStage stage = CHAIN_STAGE_UNKNOWN;

    std::string summary;
    std::string process;
    std::string src_ip;
    std::string dst_ip;
    std::string url;
    std::string sni;
    std::string rule;
    std::string session_id;
    std::string trace_id;
    std::string span_id;
    std::string mcp_method;
    std::string mcp_object_type;
    std::string mcp_object_name;
    std::string policy_inventory_status;
    uint64_t policy_inventory_version = 0;
    std::vector<McpDrift> mcp_drifts;
    std::string policy_inventory_inspection_status;
    std::string a2a_operation;
    std::string a2a_agent_name;
    std::string a2a_skill_id;
    std::string a2a_task_id;
    std::string a2a_task_state;

    int linked_to = -1;
    std::string link_type;
};



// ==============================
// 3. FEATURE STATE (SLIDING WINDOW)
// ==============================
//
// Aggregated behavioral features per entity (key).
// Window is implicit via timestamps + cleanup.
//

struct Features {
    
    // ---- Runtime signals ----
    int ipc_count = 0;
    int proc_ai_count = 0;
    int net_conn_count = 0;
    int proc_behavior_count = 0;
    int secret_access_count = 0;
    int lateral_movement_count = 0;

    // ---- Network signals ----
    int tls_burst = 0;
    int small_req = 0;
    int ja3_hits = 0;
    int long_tls_sessions = 0;
    int repetitive_tls_patterns = 0;
    int anomaly_count = 0;

    // ---- LLM provider signals ----
    int sni_llm_hits = 0;
    int dns_llm_hits = 0;
    int cert_llm_hits = 0;
    int asn_llm_hits = 0;
    int provider_usage_count = 0;
    int ai_gateway_context_count = 0;
    int corporate_data_context_count = 0;

    // ---- HTTP / API behavior ----
    int http_patterns = 0;
    int mcp_http_count = 0;
    int rest_api_calls = 0;
    int rest_auth_failures = 0;
    int rest_data_exfil = 0;
    int rest_rate_limit_hits = 0;
    int rest_endpoint_probes = 0;
    int shadow_api_count = 0;
    int rest_ssrf = 0;
    int rest_jwt_abuse = 0;
    int user_fraud_context_count = 0;
    int tool_list_count = 0;
    int tool_call_count = 0;
    int resource_access_count = 0;
    int prompt_injection_count = 0;
    int tool_abuse_count = 0;
    int chain_stage_count = 0;
    int attack_pipeline_count = 0;
    int inventory_discovery_count = 0;
    int inventory_change_count = 0;
    int unknown_tool_count = 0;
    int unknown_resource_count = 0;
    int unknown_prompt_count = 0;
    int endpoint_drift_count = 0;
    int prompt_access_count = 0;
    int sampling_request_count = 0;
    int elicitation_request_count = 0;
    int a2a_http_count = 0;
    int a2a_agent_card_count = 0;
    int a2a_agent_card_change_count = 0;
    int a2a_message_send_count = 0;
    int a2a_task_access_count = 0;
    int a2a_task_cancel_count = 0;
    int a2a_push_notification_count = 0;
    int a2a_artifact_exfil_count = 0;
    int a2a_auth_required_count = 0;
    int a2a_unknown_agent_count = 0;
    // source_mask tracks which independent sensors contributed evidence.
    // stage_mask tracks the attack-chain phases observed for this entity.
    // Both are bit masks to keep update/scoring cheap in the streaming loop.
    int source_mask = 0;
    int stage_mask = 0;
    std::vector<Evidence> timeline;
    bool ordered_prompt_tool = false;
    bool ordered_tool_network = false;
    bool ordered_llm_mcp_tool = false;
    bool ordered_shell_network = false;

    // ---- Temporal correlation ----
    long last_ipc = 0;
    long last_tls = 0;
    long last_net = 0;
    long last_runtime = 0;
    long last_ai_gateway = 0;
    long last_corporate_data = 0;
    long last_http = 0;
    long last_tool = 0;
    long last_prompt = 0;
    long last_lateral = 0;
    long last_inventory = 0;
    long last_rest = 0;
    long last_a2a = 0;
    long last_fraud_context = 0;
    long last_unknown_object = 0;

    // ---- Window control ----
    long first_seen = 0;
    long last_seen = 0;
};

// ==============================
// RISK CLASSIFICATION
// ==============================

enum RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

std::string lowerCopy(const std::string& value);
bool containsAny(const std::string& haystack, const std::vector<std::string>& needles);
std::string authenticatedIdentityKey(const std::string& gateway, const std::string& principal);
std::string makeKey(const Event& e);
bool isMeaningfulIdentity(const std::string& value);
std::string normalizeIdentity(const std::string& value);
long eventTimeMillis(long event_time, long observed_time = 0);
void normalizeEvent(Event& event);
bool isAIJA3(const std::string& ja3);
bool isLLMProviderIndicator(const std::string& value);
bool isAIGatewayIndicator(const std::string& value);
ChainStage stageForSignal(SignalType signal);
std::string signalName(SignalType signal);
std::string sourceName(int source);
std::string stageName(ChainStage stage);
// Cache body-derived predicates before retaining a compact window observation.
struct FeatureHints { bool shell_like, mcp_context, gateway_body; };
void updateFeatures(Features& f, const Event& e, const FeatureHints* hints = nullptr);

class FeatureWindow {
    struct Sample { Event event; FeatureHints hints; };
    std::deque<Sample> events_;
    void rebuild();
public:
    static constexpr size_t max_events = 4096;
    Features features;
    void add(const Event& event, long now, long ttl_ms);
    bool expire(long now, long ttl_ms); // false means the entire window expired.
    size_t size() const { return events_.size(); }
};
double scoreAPI(const Features& f);
bool hasThreatEvidence(const Features& f);
RiskLevel classify(double score);
std::string describeFindingTitle(const Features& f);
std::string describeAttackChain(const Features& f);

#endif /* DETECTION_H */
