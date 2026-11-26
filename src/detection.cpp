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

#include "detection.h"
#include "cobject.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <unordered_map>
#include <set>

std::string signalName(SignalType signal);

namespace {

const int STAGE_RUNTIME  = 1 << 0;
const int STAGE_MCP      = 1 << 1;
const int STAGE_NETWORK  = 1 << 2;
const int STAGE_PROVIDER = 1 << 3;
const int STAGE_PROMPT   = 1 << 4;
const int STAGE_TOOL     = 1 << 5;
const int STAGE_LATERAL  = 1 << 6;
const int STAGE_DATA     = 1 << 7;
const int STAGE_SHELL    = 1 << 8;
const int STAGE_REST_API = 1 << 9;
const int STAGE_A2A      = 1 << 10;
const size_t MAX_TIMELINE_EVENTS = 24;

// Count active bits in a small mask. This is used to reward multi-stage
// pipelines: an entity with runtime + MCP + tool + network evidence is more
// suspicious than an entity with a single isolated alert.
int popcount(int value) {
    int count = 0;
    while (value != 0) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

struct ScoringConfig {
    std::unordered_map<std::string, double> values;

    double get(const std::string& key) const {
        auto it = values.find(key);
        return it == values.end() ? 0.0 : it->second;
    }
};

YAML::Node findYamlPath(const YAML::Node& root, const std::string& path) {
    // BUGFIX (2026-09-28): the previous body did `node = node[part]` in the
    // loop. YAML::Node is a reference-counted handle, and its operator=
    // rewrites the data the LEFT-HAND side currently points to rather than
    // just repointing the local variable. Since `node` starts out aliasing
    // the caller's `root` (via the copy `YAML::Node node = root;`), the very
    // first `node = node[part]` collapsed the shared root document down to
    // that one child, and every subsequent top-level call to this function
    // (one per scoring_weights.yaml key, see scoringConfig() below) saw an
    // already-collapsed root and returned "not found". In practice only the
    // first key ScoringConfig::values happened to iterate to ever loaded;
    // every other threshold/signal/chain/temporal weight silently kept its
    // compiled-in default no matter what the YAML file said.
    //
    // node.reset(child) instead makes `node` point at `child`'s data without
    // writing through to whatever `node` used to alias, so `root` (and the
    // caller's copy of it) is left untouched across repeated calls.
    YAML::Node node = root;
    size_t start = 0;

    while (start < path.size()) {
        size_t end = path.find('.', start);
        std::string part = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
        node.reset(node[part]);
        if (!node) return YAML::Node();
        if (end == std::string::npos) break;
        start = end + 1;
    }

    return node;
}

ScoringConfig defaultScoringConfig() {
    ScoringConfig cfg;
    cfg.values = {
        {"thresholds.critical", 0.90},
        {"thresholds.high", 0.70},
        {"thresholds.medium", 0.45},
        {"base.max_score", 1.00},
        {"base.stage_cap", 0.30},
        {"base.stage_weight", 0.06},
        {"base.sources_2", 0.10},
        {"base.sources_3", 0.05},

        {"signals.proc_ai", 0.12},
        {"signals.ipc", 0.18},
        {"signals.mcp_http", 0.16},
        {"signals.a2a_http", 0.14},
        {"signals.a2a_agent_card_change", 0.18},
        {"signals.a2a_message_send_with_runtime", 0.12},
        {"signals.a2a_push_notification", 0.16},
        {"signals.a2a_artifact_exfil", 0.25},
        {"signals.a2a_auth_required", 0.12},
        {"signals.a2a_unknown_agent", 0.20},
        {"signals.ai_provider_usage", 0.14},
        {"signals.ai_gateway_context", 0.10},
        {"signals.corporate_data_context", 0.10},
        {"signals.tool_call", 0.16},
        {"signals.prompt_injection", 0.22},
        {"signals.tool_abuse", 0.22},
        {"signals.inventory_discovery", 0.05},
        {"signals.inventory_change", 0.18},
        {"signals.endpoint_drift", 0.18},
        {"signals.unknown_tool", 0.24},
        {"signals.unknown_object", 0.20},
        {"signals.sampling_request", 0.16},
        {"signals.elicitation_request", 0.18},
        {"signals.shell_network", 0.12},
        {"signals.lateral_movement", 0.25},
        {"signals.secret_or_resource_access", 0.16},
        {"signals.tls_anomaly", 0.12},
        {"signals.rest_api_calls", 0.08},
        {"signals.rest_auth_failures", 0.18},
        {"signals.rest_data_exfil", 0.25},
        {"signals.rest_rate_limit", 0.12},
        {"signals.rest_endpoint_probe", 0.08},
        {"signals.shadow_api", 0.18},
        {"signals.rest_ssrf", 0.22},
        {"signals.rest_jwt_abuse", 0.10},
        {"signals.user_fraud_context", 0.04},

        {"chains.runtime_mcp_network", 0.25},
        {"chains.runtime_a2a_network", 0.22},
        {"chains.corporate_data_provider", 0.16},
        {"chains.corporate_data_gateway", 0.20},
        {"chains.corporate_data_runtime_provider", 0.25},
        {"chains.a2a_mcp_tool", 0.25},
        {"chains.a2a_rest_data", 0.18},
        {"chains.mcp_tool_runtime_network", 0.25},
        {"chains.mcp_unknown_inventory", 0.25},
        {"chains.endpoint_drift_with_activity", 0.18},
        {"chains.inventory_change_with_activity", 0.20},
        {"chains.prompt_tool_network", 0.30},
        {"chains.ordered_prompt_tool_network", 0.20},
        {"chains.lateral_ai_activity", 0.30},
        {"chains.ordered_shell_lateral", 0.15},
        {"chains.multi_stage_tool_pipeline", 0.25},
        {"chains.ordered_llm_mcp_tool", 0.15},
        {"chains.user_fraud_abuse", 0.20},
        {"chains.user_fraud_auth_failure", 0.12},
        {"chains.user_fraud_data_exfil", 0.12},
        {"chains.rest_mcp", 0.12},
        {"chains.rest_a2a", 0.12},
        {"chains.mcp_a2a", 0.14},
        {"chains.rest_runtime", 0.15},
        {"chains.rest_secret_or_exfil", 0.15},
        {"chains.rest_auth_tool", 0.18},

        {"temporal.rest_runtime", 0.10},
        {"temporal.rest_http", 0.08},
        {"temporal.fraud_rest_abuse", 0.10},
        {"temporal.a2a_http", 0.08},
        {"temporal.a2a_runtime", 0.10},
        {"temporal.runtime_http", 0.10},
        {"temporal.prompt_tool", 0.15},
        {"temporal.ipc_tls", 0.12},
        {"temporal.inventory_unknown", 0.14},
        {"temporal.corporate_data_provider", 0.12},
        {"temporal.corporate_data_gateway", 0.12}
    };
    return cfg;
}

const ScoringConfig& scoringConfig() {
    static ScoringConfig cfg = [] {
        ScoringConfig loaded = defaultScoringConfig();

        std::string path = CObject::scoring_weights_path;
        const char* env_path = std::getenv("ALTPROBE_SCORING_WEIGHTS");
        if (path.empty() && env_path) path = env_path;
        if (path.empty()) {
            CObject::SysLog((char*)"[Scoring] scoring_weights path is empty; using built-in weights");
            return loaded;
        }

        try {
            YAML::Node root = YAML::LoadFile(path);
            if (!root || !root.IsMap()) {
                std::string msg = "[Scoring] invalid scoring_weights YAML; using built-in weights: ";
                msg.append(path);
                CObject::SysLog((char*)msg.c_str());
                return loaded;
            }

            // BUGFIX (2026-09-28): each key is now converted in its own
            // try/catch. Previously a single key with the wrong YAML type
            // (e.g. a quoted string where a number was expected) threw out
            // of this loop into the outer catch below, which discarded ALL
            // overrides read so far -- one typo in the file silently
            // defaulted every other correctly-specified weight too, not
            // just the bad key. A per-key failure now only forfeits that
            // one key.
            size_t loaded_count = 0;
            std::vector<std::string> invalid_keys;
            for (auto& entry : loaded.values) {
                YAML::Node node = findYamlPath(root, entry.first);
                if (!node || !node.IsScalar()) continue;
                try {
                    entry.second = node.as<double>();
                    loaded_count++;
                } catch (const std::exception& e) {
                    invalid_keys.push_back(entry.first + " (" + e.what() + ")");
                }
            }

            // BUGFIX (2026-09-28): previously nothing was logged about which
            // keys actually took effect, so a mistyped key name (e.g.
            // "treshold.high") or a stray key under the wrong section looked
            // identical to a successful load -- there was no way to tell
            // the two apart short of reading detection.cpp's source. This
            // summary is the acceptance signal for "the file is being read":
            // it names every key that failed to convert, and states how
            // many of the ~70 known keys the file actually overrode (a
            // partial file -- most users only override a handful of
            // weights -- is expected and not itself a problem).
            std::string summary = "[Scoring] scoring_weights.yaml applied ";
            summary.append(std::to_string(loaded_count));
            summary.append("/");
            summary.append(std::to_string(loaded.values.size()));
            summary.append(" known keys from ");
            summary.append(path);
            if (!invalid_keys.empty()) {
                summary.append("; invalid (kept built-in default): ");
                for (size_t i = 0; i < invalid_keys.size(); ++i) {
                    if (i) summary.append(", ");
                    summary.append(invalid_keys[i]);
                }
            }
            CObject::SysLog((char*)summary.c_str());
        } catch (const std::exception& e) {
            std::string msg = "[Scoring] cannot load scoring_weights YAML; using built-in weights: ";
            msg.append(path);
            msg.append(" error=");
            msg.append(e.what());
            CObject::SysLog((char*)msg.c_str());
            return loaded;
        } catch (...) {
            std::string msg = "[Scoring] cannot load scoring_weights YAML; using built-in weights: ";
            msg.append(path);
            CObject::SysLog((char*)msg.c_str());
            return loaded;
        }

        return loaded;
    }();

    return cfg;
}

// Remember which telemetry source produced evidence for the entity. Multiple
// independent sources (for example Proxy + Modsecurity) increase
// confidence because they observe different layers of the same behavior.
void markSource(Features& f, const Event& e) {
    // LLM evaluates existing HTTP telemetry; it is not another observed layer.
    if (e.source == 5) return;
    if (e.source > 0 && e.source < 31)
        f.source_mask |= (1 << e.source);
}

bool isShellLike(const Event& e) {
    std::string v = lowerCopy(e.process + " " + e.command + " " + e.request_body + " " + e.url);
    return containsAny(v, {
        "shell",
        "bash",
        "sh ",
        "zsh",
        "cmd.exe",
        "powershell",
        "subprocess",
        "exec"
    });
}

bool isMcpContext(const Event& e) {
    if (!e.mcp_method.empty() ||
        !e.mcp_object_type.empty() ||
        !e.mcp_object_name.empty() ||
        !e.policy_inventory_status.empty())
        return true;

    std::string v = lowerCopy(
        e.url + " " +
        e.user_agent + " " +
        e.request_body + " " +
        e.response_body
    );

    return containsAny(v, {
        "\"jsonrpc\"",
        "mcp-session-id",
        "mcp-protocol-version",
        "modelcontextprotocol",
        "tools/list",
        "tools/call",
        "resources/read",
        "prompts/get",
        "/mcp",
        "/sse"
    });
}

std::string firstNonEmpty(
    const std::string& a,
    const std::string& b,
    const std::string& c = ""
) {
    if (!a.empty()) return a;
    if (!b.empty()) return b;
    return c;
}

std::string shortText(const std::string& value, size_t limit = 160) {
    if (value.size() <= limit)
        return value;

    return value.substr(0, limit) + "...";
}

int findLastStageIndex(const Features& f, ChainStage stage) {
    for (int i = (int)f.timeline.size() - 1; i >= 0; --i) {
        if (f.timeline[(size_t)i].stage == stage)
            return i;
    }
    return -1;
}

void appendEvidence(Features& f, const Event& e, ChainStage stage) {
    Evidence ev;
    ev.guard = e.guard;
    ev.llm_guard = e.llm_guard;
    ev.ts = e.ts;
    ev.source = e.source;
    ev.signal = e.signal;
    ev.stage = stage;
    ev.process = e.process;
    ev.session_id = e.session_id;
    ev.src_ip = e.src_ip;
    ev.dst_ip = e.dst_ip;
    ev.url = e.url;
    ev.sni = e.sni;
    ev.rule = e.rule;
    ev.trace_id = e.trace_id;
    ev.span_id = e.span_id;
    ev.mcp_method = e.mcp_method;
    ev.mcp_object_type = e.mcp_object_type;
    ev.mcp_object_name = e.mcp_object_name;
    ev.policy_inventory_status = e.policy_inventory_status;
    ev.policy_inventory_version = e.policy_inventory_version;
    ev.mcp_drifts = e.mcp_drifts;
    ev.policy_inventory_inspection_status = e.policy_inventory_inspection_status;
    ev.a2a_operation = e.a2a_operation;
    ev.a2a_agent_name = e.a2a_agent_name;
    ev.a2a_skill_id = e.a2a_skill_id;
    ev.a2a_task_id = e.a2a_task_id;
    ev.a2a_task_state = e.a2a_task_state;

    ev.summary = signalName(e.signal);
    std::string detail = firstNonEmpty(e.mcp_object_name, e.a2a_agent_name, e.url);
    if (detail.empty())
        detail = e.dst_ip;
    if (detail.empty())
        detail = firstNonEmpty(e.a2a_task_id, e.mcp_method, e.process);
    if (detail.empty())
        detail = firstNonEmpty(e.process, e.file_path, e.command);
    if (!detail.empty()) {
        ev.summary.append(" ");
        ev.summary.append(shortText(detail));
    }

    // Simple graph: link this event to related previous evidence by session id,
    // same src_ip, or same url within a time window.
    if (!f.timeline.empty()) {
        int n = (int)f.timeline.size();
        for (int i = n - 1; i >= 0 && i >= n - 5; --i) {
            const auto& prev = f.timeline[i];
            if (!ev.session_id.empty() && prev.session_id == ev.session_id &&
                std::labs(prev.ts - ev.ts) <= 30000) {
                ev.linked_to = i;
                ev.link_type = "same_session";
                break;
            }
            if (prev.linked_to == -1 &&
                !ev.src_ip.empty() &&
                prev.src_ip == ev.src_ip &&
                std::labs(prev.ts - ev.ts) <= 30000) {
                ev.linked_to = i;
                ev.link_type = "same_src";
                break;
            }
        }
    }

    if (f.timeline.size() >= MAX_TIMELINE_EVENTS)
        f.timeline.erase(f.timeline.begin());

    f.timeline.push_back(ev);

    // Update ordered chain flags for causality analysis
    f.ordered_prompt_tool = f.ordered_prompt_tool ||
        (stage == CHAIN_STAGE_TOOL && findLastStageIndex(f, CHAIN_STAGE_PROMPT) >= 0);
    f.ordered_tool_network = f.ordered_tool_network ||
        (stage == CHAIN_STAGE_NETWORK && findLastStageIndex(f, CHAIN_STAGE_TOOL) >= 0);
    f.ordered_llm_mcp_tool = f.ordered_llm_mcp_tool ||
        (stage == CHAIN_STAGE_TOOL &&
         findLastStageIndex(f, CHAIN_STAGE_LLM) >= 0 &&
         findLastStageIndex(f, CHAIN_STAGE_MCP) >= 0);
    f.ordered_llm_mcp_tool = f.ordered_llm_mcp_tool ||
        (stage == CHAIN_STAGE_TOOL &&
         findLastStageIndex(f, CHAIN_STAGE_A2A) >= 0);
    f.ordered_shell_network = f.ordered_shell_network ||
        (stage == CHAIN_STAGE_NETWORK && findLastStageIndex(f, CHAIN_STAGE_SHELL) >= 0);
}

void appendContextEvidence(Features& f, const Event& e, SignalType signal, ChainStage stage) {
    Event context = e;
    context.signal = signal;
    appendEvidence(f, context, stage);
}

}

// Return a lowercase copy for simple protocol/body heuristics.
// The detector intentionally uses deterministic string rules here: these
// signals are explainable, cheap to run in the collector, and easy to tune
// alongside IDS rules without introducing an ML dependency.
std::string lowerCopy(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return out;
}

bool containsAny(const std::string& haystack, const std::vector<std::string>& needles) {
    for (const auto& needle : needles) {
        if (haystack.find(needle) != std::string::npos)
            return true;
    }

    return false;
}

// ==============================
// ENTITY KEY FUNCTION
// ==============================





long eventTimeMillis(long event_time, long observed_time) {
    if (event_time > 0) return event_time;
    if (observed_time > 0) return observed_time;
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void normalizeEvent(Event& e) {
    if ((e.request_truncated || e.response_truncated) && e.guard.inspection_status == "complete")
        e.guard.inspection_status = "truncated";
    if (e.observed_ts <= 0) e.observed_ts = eventTimeMillis(0);
    e.ts = eventTimeMillis(e.ts, e.observed_ts);
    e.session_id = normalizeIdentity(e.session_id);
    e.agent_key = normalizeIdentity(e.agent_key);
    if (e.application_protocol.empty())
        e.application_protocol = !e.a2a_operation.empty() ? "a2a" : (!e.mcp_method.empty() ? "mcp" : "");
    if (e.request_original_size == 0 && !e.request_missing) e.request_original_size = e.request_body.size();
    if (e.response_original_size == 0 && !e.response_missing) e.response_original_size = e.response_body.size();
}





// ==============================
// PROVIDER / HTTP HEURISTICS
// ==============================

bool isAIJA3(const std::string& ja3) {
    std::string v = lowerCopy(ja3);

    return containsAny(v, {
        "python",
        "node",
        "grpc",
        "openai",
        "anthropic",
        "google",
        "cohere"
    });
}

bool isLLMProviderIndicator(const std::string& value) {
    std::string v = lowerCopy(value);

    return containsAny(v, {
        "openai.com",
        "api.openai.com",
        "anthropic.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "gemini",
        "cohere.ai",
        "mistral.ai",
        "openrouter.ai",
        "api.groq.com",
        "api.together.xyz",
        "api.perplexity.ai",
        "api.deepseek.com",
        "deepseek.com",
        "api.x.ai",
        "bedrock-runtime",
        "amazonaws.com/bedrock",
        "huggingface.co",
        "replicate.com",
        "ollama",
        "localhost:11434"
    });
}

bool isAIGatewayIndicator(const std::string& value) {
    std::string v = lowerCopy(value);

    return containsAny(v, {
        "litellm",
        "x-litellm",
        "litellm_proxy",
        "openai-compatible",
        "ai-gateway",
        "ai_gateway",
        "/v1/chat/completions",
        "/v1/responses",
        "/v1/embeddings",
        "/v1/rerank",
        "/v1/models"
    });
}

ChainStage stageForSignal(SignalType signal) {
    switch (signal) {
        case SIG_PROC_SPAWN_AI:
        case SIG_PROC_BEHAVIOR:
        case SIG_MCP_IPC:
        case SIG_MCP_STDIO:
            return CHAIN_STAGE_RUNTIME;

        case SIG_MCP_HTTP:
        case SIG_MCP_TOOL_LIST:
        case SIG_MCP_CHAIN_STAGE:
        case SIG_MCP_INVENTORY_DISCOVERY:
        case SIG_MCP_INVENTORY_CHANGE:
        case SIG_MCP_ENDPOINT_DRIFT:
            return CHAIN_STAGE_MCP;

        case SIG_PROMPT_INJECTION:
        case SIG_MCP_PROMPT_ACCESS:
            return CHAIN_STAGE_PROMPT;

        case SIG_MCP_TOOL_CALL:
        case SIG_MCP_UNKNOWN_TOOL:
            return CHAIN_STAGE_TOOL;

        case SIG_TOOL_ABUSE:
        case SIG_RCE:
            return CHAIN_STAGE_SHELL;

        case SIG_PROC_NET_CLIENT:
        case SIG_TLS_JA3_AI:
        case SIG_SMALL_TLS_REQ:
        case SIG_TLS_BURST:
        case SIG_LONG_TLS_SESSION:
        case SIG_REPETITIVE_TLS_PATTERN:
        case SIG_ANOMALY_BEHAVIOR:
            return CHAIN_STAGE_NETWORK;

        case SIG_TLS_SNI_LLM:
        case SIG_DNS_LLM:
        case SIG_TLS_CERT_LLM:
        case SIG_ASN_LLM:
        case SIG_AI_PROVIDER_USAGE:
        case SIG_AI_GATEWAY_CONTEXT:
        case SIG_MCP_SAMPLING_REQUEST:
            return CHAIN_STAGE_LLM;

        case SIG_LATERAL_MOVEMENT:
            return CHAIN_STAGE_LATERAL;

        case SIG_SECRET_ACCESS:
        case SIG_CORPORATE_DATA_CONTEXT:
        case SIG_MCP_RESOURCE_ACCESS:
        case SIG_MCP_UNKNOWN_RESOURCE:
        case SIG_MCP_UNKNOWN_PROMPT:
        case SIG_MCP_ELICITATION_REQUEST:
        case SIG_PATH_TRAVERSAL:
        case SIG_LFI:
        case SIG_RFI:
            return CHAIN_STAGE_DATA;

        case SIG_A2A_HTTP:
        case SIG_A2A_AGENT_CARD_DISCOVERY:
        case SIG_A2A_AGENT_CARD_CHANGE:
        case SIG_A2A_MESSAGE_SEND:
        case SIG_A2A_TASK_ACCESS:
        case SIG_A2A_TASK_CANCEL:
        case SIG_A2A_PUSH_NOTIFICATION:
        case SIG_A2A_UNKNOWN_AGENT:
            return CHAIN_STAGE_A2A;

        case SIG_A2A_ARTIFACT_EXFIL:
        case SIG_A2A_AUTH_REQUIRED:
            return CHAIN_STAGE_DATA;

        case SIG_REST_API_CALL:
        case SIG_REST_AUTH_BYPASS:
        case SIG_REST_DATA_EXFIL:
        case SIG_REST_RATE_LIMIT_ABUSE:
        case SIG_REST_ENDPOINT_PROBE:
        case SIG_SHADOW_API:
        case SIG_REST_SSRF:
        case SIG_REST_JWT_ABUSE:
        case SIG_USER_FRAUD_CONTEXT:
            return CHAIN_STAGE_REST_API;

        case SIG_ATTACK_PIPELINE:
        case SIG_PROTOCOL_VIOLATION:
        case SIG_SCANNER:
        case SIG_SQLI:
        case SIG_XSS:
        case SIG_ANOMALY:
            return CHAIN_STAGE_REST_API;

        default:
            return CHAIN_STAGE_UNKNOWN;
    }
}



std::string sourceName(int source) {
    switch (source) {
        case 1: return "runtime";
        case 2: return "network";
        case 3: return "proxy";
        case 5: return "llm_guard";
        case 4: return "modsec";
        default: return "unknown";
    }
}

std::string stageName(ChainStage stage) {
    switch (stage) {
        case CHAIN_STAGE_RUNTIME: return "runtime";
        case CHAIN_STAGE_LLM: return "llm";
        case CHAIN_STAGE_MCP: return "mcp";
        case CHAIN_STAGE_PROMPT: return "prompt";
        case CHAIN_STAGE_TOOL: return "tool";
        case CHAIN_STAGE_SHELL: return "shell";
        case CHAIN_STAGE_NETWORK: return "network";
        case CHAIN_STAGE_LATERAL: return "lateral";
        case CHAIN_STAGE_DATA: return "data";
        case CHAIN_STAGE_REST_API: return "rest_api";
        case CHAIN_STAGE_A2A: return "a2a";
        default: return "unknown";
    }
}

// ==============================
// FEATURE UPDATE
// ==============================

void updateFeatures(Features& f, const Event& e, const FeatureHints* hints) {

    if (f.first_seen == 0 || e.ts < f.first_seen)
        f.first_seen = e.ts;

    f.last_seen = std::max(f.last_seen, e.ts);
    markSource(f, e);
    ChainStage event_stage = stageForSignal(e.signal);
    if (event_stage == CHAIN_STAGE_UNKNOWN && !e.mcp_drifts.empty()) event_stage = CHAIN_STAGE_MCP;
    if (event_stage == CHAIN_STAGE_SHELL && !(hints ? hints->shell_like : isShellLike(e)))
        event_stage = CHAIN_STAGE_TOOL;
    if (event_stage != CHAIN_STAGE_UNKNOWN)
        appendEvidence(f, e, event_stage);

    // Convert the normalized signal into durable behavioral features. The
    // correlator does not emit on single events; it scores the aggregate state
    // for the entity over the sliding window.
    switch (e.signal) {
        case SIG_MCP_IPC:
        case SIG_MCP_STDIO:
            // IPC is a strong MCP/runtime indicator because many MCP servers
            // are local tool bridges that communicate over pipes or Unix
            // sockets before making network calls.
            f.ipc_count++;
            f.last_ipc = e.ts;
            f.stage_mask |= STAGE_RUNTIME | STAGE_MCP;
            break;

        case SIG_PROC_SPAWN_AI:
            f.proc_ai_count++;
            f.last_runtime = e.ts;
            f.stage_mask |= STAGE_RUNTIME;
            break;

        case SIG_PROC_NET_CLIENT:
            f.net_conn_count++;
            f.last_net = e.ts;
            f.stage_mask |= STAGE_RUNTIME | STAGE_NETWORK;
            break;

        case SIG_PROC_BEHAVIOR:
            f.proc_behavior_count++;
            f.stage_mask |= STAGE_RUNTIME | STAGE_TOOL;
            break;

        case SIG_SECRET_ACCESS:
            f.secret_access_count++;
            if (e.source == 1) {
                f.proc_behavior_count++;
                f.stage_mask |= STAGE_RUNTIME | STAGE_DATA;
            } else {
                f.stage_mask |= STAGE_DATA | STAGE_NETWORK;
            }
            break;

        case SIG_LATERAL_MOVEMENT:
            f.lateral_movement_count++;
            f.last_lateral = e.ts;
            f.stage_mask |= STAGE_LATERAL | STAGE_NETWORK;
            break;

        case SIG_TLS_JA3_AI:
            f.ja3_hits++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK;
            break;

        case SIG_SMALL_TLS_REQ:
            f.small_req++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK;
            break;

        case SIG_TLS_BURST:
            f.tls_burst++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK;
            break;

        case SIG_LONG_TLS_SESSION:
            f.long_tls_sessions++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK;
            break;

        case SIG_REPETITIVE_TLS_PATTERN:
            f.repetitive_tls_patterns++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK;
            break;

        case SIG_ANOMALY_BEHAVIOR:
            f.anomaly_count++;
            f.last_net = e.ts;
            f.stage_mask |= STAGE_NETWORK;
            break;

        case SIG_HTTP_PATTERN:
        case SIG_MCP_HTTP:
            f.http_patterns++;
            f.mcp_http_count++;
            f.last_http = e.ts;
            f.stage_mask |= STAGE_MCP;
            break;

        case SIG_MCP_TOOL_LIST:
            f.http_patterns++;
            f.mcp_http_count++;
            f.tool_list_count++;
            f.inventory_discovery_count++;
            f.last_http = e.ts;
            f.last_inventory = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_TOOL;
            break;

        case SIG_MCP_TOOL_CALL:
            f.http_patterns++;
            f.mcp_http_count++;
            f.tool_call_count++;
            f.last_http = e.ts;
            f.last_tool = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_TOOL;
            break;

        case SIG_MCP_RESOURCE_ACCESS:
            f.http_patterns++;
            f.mcp_http_count++;
            f.resource_access_count++;
            f.last_http = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_DATA;
            break;

        case SIG_MCP_INVENTORY_DISCOVERY:
            f.http_patterns++;
            f.mcp_http_count++;
            f.inventory_discovery_count++;
            f.last_inventory = e.ts;
            f.stage_mask |= STAGE_MCP;
            break;

        case SIG_MCP_INVENTORY_CHANGE:
            f.http_patterns++;
            f.mcp_http_count++;
            f.inventory_change_count++;
            f.last_inventory = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_TOOL | STAGE_DATA;
            break;

        case SIG_MCP_UNKNOWN_TOOL:
            f.http_patterns++;
            f.mcp_http_count++;
            f.unknown_tool_count++;
            f.tool_call_count++;
            f.last_tool = e.ts;
            f.last_unknown_object = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_TOOL;
            break;

        case SIG_MCP_UNKNOWN_RESOURCE:
            f.http_patterns++;
            f.mcp_http_count++;
            f.unknown_resource_count++;
            f.resource_access_count++;
            f.last_unknown_object = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_DATA;
            break;

        case SIG_MCP_UNKNOWN_PROMPT:
            f.http_patterns++;
            f.mcp_http_count++;
            f.unknown_prompt_count++;
            f.prompt_access_count++;
            f.last_prompt = e.ts;
            f.last_unknown_object = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_PROMPT | STAGE_DATA;
            break;

        case SIG_MCP_ENDPOINT_DRIFT:
            f.http_patterns++;
            f.mcp_http_count++;
            f.endpoint_drift_count++;
            f.last_inventory = e.ts;
            f.stage_mask |= STAGE_MCP;
            break;

        case SIG_MCP_PROMPT_ACCESS:
            f.http_patterns++;
            f.mcp_http_count++;
            f.prompt_access_count++;
            f.last_prompt = e.ts;
            f.stage_mask |= STAGE_MCP | STAGE_PROMPT;
            break;

        case SIG_MCP_SAMPLING_REQUEST:
            f.http_patterns++;
            f.mcp_http_count++;
            f.sampling_request_count++;
            f.provider_usage_count++;
            f.stage_mask |= STAGE_MCP | STAGE_PROVIDER;
            break;

        case SIG_MCP_ELICITATION_REQUEST:
            f.http_patterns++;
            f.mcp_http_count++;
            f.elicitation_request_count++;
            f.resource_access_count++;
            f.stage_mask |= STAGE_MCP | STAGE_DATA;
            break;

        case SIG_A2A_HTTP:
            f.http_patterns++;
            f.a2a_http_count++;
            f.last_a2a = e.ts;
            f.last_http = e.ts;
            f.stage_mask |= STAGE_A2A;
            break;

        case SIG_A2A_AGENT_CARD_DISCOVERY:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_agent_card_count++;
            f.last_a2a = e.ts;
            f.last_inventory = e.ts;
            f.stage_mask |= STAGE_A2A;
            break;

        case SIG_A2A_AGENT_CARD_CHANGE:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_agent_card_change_count++;
            f.last_a2a = e.ts;
            f.last_inventory = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_DATA;
            break;

        case SIG_A2A_MESSAGE_SEND:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_message_send_count++;
            f.last_a2a = e.ts;
            f.last_http = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_TOOL;
            break;

        case SIG_A2A_TASK_ACCESS:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_task_access_count++;
            f.last_a2a = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_DATA;
            break;

        case SIG_A2A_TASK_CANCEL:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_task_cancel_count++;
            f.last_a2a = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_TOOL;
            break;

        case SIG_A2A_PUSH_NOTIFICATION:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_push_notification_count++;
            f.last_a2a = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_NETWORK;
            break;

        case SIG_A2A_ARTIFACT_EXFIL:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_artifact_exfil_count++;
            f.secret_access_count++;
            f.last_a2a = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_DATA | STAGE_NETWORK;
            break;

        case SIG_A2A_AUTH_REQUIRED:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_auth_required_count++;
            f.last_a2a = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_DATA;
            break;

        case SIG_A2A_UNKNOWN_AGENT:
            f.http_patterns++;
            f.a2a_http_count++;
            f.a2a_unknown_agent_count++;
            f.last_a2a = e.ts;
            f.stage_mask |= STAGE_A2A | STAGE_DATA;
            break;

        case SIG_REST_API_CALL:
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API;
            break;

        case SIG_REST_AUTH_BYPASS:
            f.rest_auth_failures++;
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API | STAGE_DATA;
            break;

        case SIG_REST_DATA_EXFIL:
            f.rest_data_exfil++;
            f.rest_api_calls++;
            f.secret_access_count++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API | STAGE_DATA | STAGE_NETWORK;
            break;

        case SIG_REST_RATE_LIMIT_ABUSE:
            f.rest_rate_limit_hits++;
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API | STAGE_NETWORK;
            break;

        case SIG_SHADOW_API:
            f.shadow_api_count++;
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API;
            break;

        case SIG_REST_ENDPOINT_PROBE:
            f.rest_endpoint_probes++;
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API;
            break;

        case SIG_REST_SSRF:
            f.rest_ssrf++;
            f.rest_api_calls++;
            f.net_conn_count++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API | STAGE_NETWORK | STAGE_DATA;
            break;

        case SIG_REST_JWT_ABUSE:
            f.rest_jwt_abuse++;
            f.rest_auth_failures++;
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.stage_mask |= STAGE_REST_API | STAGE_DATA;
            break;

        case SIG_USER_FRAUD_CONTEXT:
            f.user_fraud_context_count++;
            f.rest_api_calls++;
            f.last_rest = e.ts;
            f.last_fraud_context = e.ts;
            f.stage_mask |= STAGE_REST_API;
            break;

        case SIG_PROMPT_INJECTION:
            // Prompt injection is not enough alone, but it becomes high risk
            // when followed by tool execution, provider calls, or lateral
            // movement in the same entity window.
            f.prompt_injection_count++;
            f.last_prompt = e.ts;
            f.stage_mask |= STAGE_PROMPT;
            if (hints ? hints->mcp_context : isMcpContext(e)) {
                f.http_patterns++;
                f.mcp_http_count++;
                f.last_http = e.ts;
                f.stage_mask |= STAGE_MCP;
            }
            break;

        case SIG_TOOL_ABUSE:
            // Tool abuse captures dangerous tool use regardless of whether it
            // was seen in HTTP body content or as a runtime process spawn.
            f.tool_abuse_count++;
            f.last_tool = e.ts;
            f.stage_mask |= STAGE_TOOL | STAGE_SHELL;
            break;

        case SIG_TLS_SNI_LLM:
            f.sni_llm_hits++;
            f.provider_usage_count++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK | STAGE_PROVIDER;
            break;

        case SIG_DNS_LLM:
            f.dns_llm_hits++;
            f.provider_usage_count++;
            f.net_conn_count++;
            f.last_net = e.ts;
            f.stage_mask |= STAGE_NETWORK | STAGE_PROVIDER;
            break;

        case SIG_TLS_CERT_LLM:
            f.cert_llm_hits++;
            f.provider_usage_count++;
            f.net_conn_count++;
            f.last_tls = e.ts;
            f.stage_mask |= STAGE_NETWORK | STAGE_PROVIDER;
            break;

        case SIG_ASN_LLM:
        case SIG_AI_PROVIDER_USAGE:
            f.asn_llm_hits++;
            f.provider_usage_count++;
            f.net_conn_count++;
            f.last_net = e.ts;
            f.stage_mask |= STAGE_NETWORK | STAGE_PROVIDER;
            break;

        case SIG_AI_GATEWAY_CONTEXT:
            f.ai_gateway_context_count++;
            f.provider_usage_count++;
            f.last_ai_gateway = e.ts;
            f.last_http = e.ts;
            f.stage_mask |= STAGE_PROVIDER;
            break;

        case SIG_CORPORATE_DATA_CONTEXT:
            f.corporate_data_context_count++;
            f.last_corporate_data = e.ts;
            f.last_http = e.ts;
            f.stage_mask |= STAGE_DATA;
            break;

        case SIG_MCP_CHAIN_STAGE:
            f.chain_stage_count++;
            f.stage_mask |= STAGE_MCP;
            break;

        case SIG_ATTACK_PIPELINE:
            f.attack_pipeline_count++;
            f.stage_mask |= STAGE_REST_API | STAGE_TOOL | STAGE_NETWORK;
            break;

        case SIG_PROTOCOL_VIOLATION:
            f.anomaly_count++;
            f.chain_stage_count++;
            f.stage_mask |= STAGE_REST_API;
            break;

        case SIG_SQLI:
        case SIG_XSS:
        case SIG_SCANNER:
        case SIG_ANOMALY:
            f.anomaly_count++;
            f.stage_mask |= STAGE_REST_API;
            break;

        case SIG_RCE:
            f.tool_abuse_count++;
            f.stage_mask |= STAGE_REST_API | STAGE_TOOL | STAGE_SHELL;
            break;

        case SIG_PATH_TRAVERSAL:
        case SIG_LFI:
        case SIG_RFI:
            f.resource_access_count++;
            f.stage_mask |= STAGE_REST_API | STAGE_DATA;
            break;

        default:
            break;
    }

    // Count each additional drift category once per operation, not once per
    // changed field/object. Do not replay source/provider/network enrichment.
    std::set<SignalType> drift_categories;
    for (const auto& drift : e.mcp_drifts) {
        if (drift.signal == e.signal || !drift_categories.insert(drift.signal).second) continue;
        switch (drift.signal) {
            case SIG_MCP_INVENTORY_CHANGE:
                ++f.inventory_change_count; f.last_inventory = e.ts;
                f.stage_mask |= STAGE_MCP | STAGE_TOOL | STAGE_DATA; break;
            case SIG_MCP_ENDPOINT_DRIFT:
                ++f.endpoint_drift_count; f.last_inventory = e.ts;
                f.stage_mask |= STAGE_MCP; break;
            case SIG_MCP_UNKNOWN_TOOL:
                ++f.unknown_tool_count; f.last_unknown_object = e.ts; f.last_tool = e.ts;
                f.stage_mask |= STAGE_MCP | STAGE_TOOL; break;
            case SIG_MCP_UNKNOWN_RESOURCE:
                ++f.unknown_resource_count; f.last_unknown_object = e.ts;
                f.stage_mask |= STAGE_MCP | STAGE_DATA; break;
            case SIG_MCP_UNKNOWN_PROMPT:
                ++f.unknown_prompt_count; f.last_unknown_object = e.ts; f.last_prompt = e.ts;
                f.stage_mask |= STAGE_MCP | STAGE_PROMPT | STAGE_DATA; break;
            default: break;
        }
    }

    // Optional frequency enrichment. Some sensors can precompute request
    // frequency; if present, fold it into the network stage.
    if (e.freq > 20) {
        f.tls_burst++;
        f.last_tls = e.ts;
        f.stage_mask |= STAGE_NETWORK;
    }

    if (!e.ja3.empty() && isAIJA3(e.ja3)) {
        f.ja3_hits += 2;
        f.stage_mask |= STAGE_NETWORK;
    }

    const bool explicit_provider_signal =
        e.signal == SIG_AI_PROVIDER_USAGE ||
        e.signal == SIG_TLS_SNI_LLM ||
        e.signal == SIG_DNS_LLM ||
        e.signal == SIG_TLS_CERT_LLM ||
        e.signal == SIG_ASN_LLM;

    bool inferred_provider_context = false;
    bool inferred_gateway_context = false;

    if (!e.sni.empty() && isLLMProviderIndicator(e.sni)) {
        f.provider_usage_count++;
        f.stage_mask |= STAGE_NETWORK | STAGE_PROVIDER;
        inferred_provider_context = true;
    }

    if (isLLMProviderIndicator(e.dst_ip) || isLLMProviderIndicator(e.url)) {
        f.provider_usage_count++;
        f.stage_mask |= STAGE_NETWORK | STAGE_PROVIDER;
        inferred_provider_context = true;
    }

    const bool known_external_provider =
        isLLMProviderIndicator(e.dst_ip) || isLLMProviderIndicator(e.sni);

    if (!known_external_provider &&
        e.signal != SIG_AI_GATEWAY_CONTEXT &&
        (isAIGatewayIndicator(e.dst_ip) ||
         isAIGatewayIndicator(e.url) ||
         isAIGatewayIndicator(e.user_agent) ||
         (hints ? hints->gateway_body : isAIGatewayIndicator(e.request_body)))) {
        f.ai_gateway_context_count++;
        f.last_ai_gateway = e.ts;
        f.stage_mask |= STAGE_PROVIDER;
        inferred_gateway_context = true;
    }

    if (inferred_provider_context && !explicit_provider_signal)
        appendContextEvidence(f, e, SIG_AI_PROVIDER_USAGE, CHAIN_STAGE_LLM);

    if (inferred_gateway_context)
        appendContextEvidence(f, e, SIG_AI_GATEWAY_CONTEXT, CHAIN_STAGE_LLM);
}

// ==============================
// ATTACK-CHAIN SCORING
// ==============================

void FeatureWindow::rebuild() {
    features = Features{};
    for (const auto& sample : events_) updateFeatures(features, sample.event, &sample.hints);
}

bool FeatureWindow::expire(long now, long ttl_ms) {
    const long cutoff = now - (ttl_ms > 0 ? ttl_ms : 90000);
    bool changed = false;
    while (!events_.empty() && events_.front().event.ts < cutoff) {
        events_.pop_front(); changed = true;
    }
    if (changed) rebuild();
    return !events_.empty();
}

void FeatureWindow::add(const Event& event, long now, long ttl_ms) {
    expire(now, ttl_ms);
    if (event.ts < now - (ttl_ms > 0 ? ttl_ms : 90000)) return;
    Sample sample{event, {isShellLike(event), isMcpContext(event), isAIGatewayIndicator(event.request_body)}};
    // Feature accumulation never inspects bodies again. Preserve their derived
    // predicates, not another copy of potentially megabyte-sized HTTP payloads.
    std::string{}.swap(sample.event.request_body);
    std::string{}.swap(sample.event.response_body);
    const bool ordered = events_.empty() || events_.back().event.ts <= event.ts;
    bool evicted = false;
    auto position = std::upper_bound(events_.begin(), events_.end(), event.ts,
        [](long ts, const Sample& value) { return ts < value.event.ts; });
    events_.insert(position, std::move(sample));
    if (events_.size() > max_events) {
        events_.pop_front(); evicted = true;
        static std::atomic<uint64_t> dropped{0};
        if (++dropped == 1 || dropped % 1000 == 0)
            CObject::SysLog((char*)"[Correlator] feature window capacity reached; oldest observation evicted");
    }
    if (ordered && !evicted) updateFeatures(features, events_.back().event, &events_.back().hints);
    else rebuild(); // Late events must not invent ordered attack-chain evidence.
}

bool hasThreatEvidence(const Features& f) {
    // Protocol context (AI gateway, tool call, provider) is useful correlation
    // evidence, but it is not proof of an attack. Without at least one
    // threat-bearing indicator, do not let the additive score reach HIGH.
    return f.prompt_injection_count > 0 ||
        f.tool_abuse_count > 0 ||
        f.lateral_movement_count > 0 ||
        f.secret_access_count > 0 ||
        f.rest_auth_failures > 0 ||
        f.rest_data_exfil > 0 ||
        f.rest_ssrf > 0 ||
        f.rest_jwt_abuse > 0 ||
        f.rest_endpoint_probes > 20 ||
        f.shadow_api_count > 0 ||
        f.unknown_tool_count > 0 ||
        f.unknown_resource_count > 0 ||
        f.unknown_prompt_count > 0 ||
        f.endpoint_drift_count > 0 ||
        f.inventory_change_count > 0 ||
        f.a2a_artifact_exfil_count > 0 ||
        f.a2a_unknown_agent_count > 0 ||
        f.a2a_agent_card_change_count > 0;
}

double scoreAPI(const Features& f) {

    double score = 0.0;
    const ScoringConfig& weights = scoringConfig();

    const bool runtime = (f.stage_mask & STAGE_RUNTIME) != 0;
    const bool mcp = (f.stage_mask & STAGE_MCP) != 0;
    const bool a2a = (f.stage_mask & STAGE_A2A) != 0;
    const bool rest_api = (f.stage_mask & STAGE_REST_API) != 0;
    const bool network = (f.stage_mask & STAGE_NETWORK) != 0;
    const bool provider = (f.stage_mask & STAGE_PROVIDER) != 0;
    const bool prompt = (f.stage_mask & STAGE_PROMPT) != 0;
    const bool tool = (f.stage_mask & STAGE_TOOL) != 0;
    const bool lateral = (f.stage_mask & STAGE_LATERAL) != 0;
    const bool data = (f.stage_mask & STAGE_DATA) != 0;
    const bool shell = (f.stage_mask & STAGE_SHELL) != 0;

    const int stages = popcount(f.stage_mask);
    const int sources = popcount(f.source_mask);

    // Base confidence comes from breadth of the chain. The cap prevents many
    // weak stages from overwhelming a few high-quality indicators.
    score += std::min(weights.get("base.stage_cap"), stages * weights.get("base.stage_weight"));
    if (sources >= 2) score += weights.get("base.sources_2");
    if (sources >= 3) score += weights.get("base.sources_3");

    if (f.proc_ai_count > 0) score += weights.get("signals.proc_ai");
    if (f.ipc_count > 0) score += weights.get("signals.ipc");
    if (f.mcp_http_count > 0) score += weights.get("signals.mcp_http");
    if (f.a2a_http_count > 0) score += weights.get("signals.a2a_http");
    if (f.a2a_agent_card_change_count > 0) score += weights.get("signals.a2a_agent_card_change");
    if (f.a2a_message_send_count > 0 && runtime) score += weights.get("signals.a2a_message_send_with_runtime");
    if (f.a2a_push_notification_count > 0) score += weights.get("signals.a2a_push_notification");
    if (f.a2a_artifact_exfil_count > 0) score += weights.get("signals.a2a_artifact_exfil");
    if (f.a2a_auth_required_count > 0) score += weights.get("signals.a2a_auth_required");
    if (f.a2a_unknown_agent_count > 0) score += weights.get("signals.a2a_unknown_agent");
    if (f.provider_usage_count > 0) score += weights.get("signals.ai_provider_usage");
    if (f.ai_gateway_context_count > 0) score += weights.get("signals.ai_gateway_context");
    if (f.corporate_data_context_count > 0) score += weights.get("signals.corporate_data_context");
    if (f.tool_call_count > 0) score += weights.get("signals.tool_call");
    if (f.prompt_injection_count > 0) score += weights.get("signals.prompt_injection");
    if (f.tool_abuse_count > 0) score += weights.get("signals.tool_abuse");
    if (f.inventory_discovery_count > 1) score += weights.get("signals.inventory_discovery");
    if (f.inventory_change_count > 0) score += weights.get("signals.inventory_change");
    if (f.endpoint_drift_count > 0) score += weights.get("signals.endpoint_drift");
    if (f.unknown_tool_count > 0) score += weights.get("signals.unknown_tool");
    if (f.unknown_resource_count > 0 || f.unknown_prompt_count > 0) score += weights.get("signals.unknown_object");
    if (f.sampling_request_count > 0) score += weights.get("signals.sampling_request");
    if (f.elicitation_request_count > 0) score += weights.get("signals.elicitation_request");
    if (shell && network) score += weights.get("signals.shell_network");
    if (f.lateral_movement_count > 0) score += weights.get("signals.lateral_movement");
    if (f.secret_access_count > 0 || f.resource_access_count > 0) score += weights.get("signals.secret_or_resource_access");

    if (f.tls_burst > 0 || f.small_req > 10 || f.repetitive_tls_patterns > 0)
        score += weights.get("signals.tls_anomaly");

    // MCP runtime + network correlation.
    // This is the classic case: runtime-contract evidence combines with
    // network/provider evidence from proxy telemetry.
    if (runtime && mcp && (network || provider))
        score += weights.get("chains.runtime_mcp_network");

    if (runtime && a2a && (network || provider))
        score += weights.get("chains.runtime_a2a_network");

    if (f.corporate_data_context_count > 0 && provider)
        score += weights.get("chains.corporate_data_provider");

    if (f.corporate_data_context_count > 0 && f.ai_gateway_context_count > 0)
        score += weights.get("chains.corporate_data_gateway");

    if (f.corporate_data_context_count > 0 && runtime && provider)
        score += weights.get("chains.corporate_data_runtime_provider");

    if (a2a && mcp && tool)
        score += weights.get("chains.a2a_mcp_tool");

    if (a2a && rest_api && data)
        score += weights.get("chains.a2a_rest_data");

    // MCP chain attack: runtime or HTTP MCP, tool execution, and
    // provider/network evidence all appear in the same entity window.
    if (mcp && tool && (runtime || f.ipc_count > 0) && (network || provider))
        score += weights.get("chains.mcp_tool_runtime_network");

    // Inventory-aware MCP drift: observed tool/resource/prompt access that is
    // absent from the Alertflex inventory is a strong sign of protocol surface
    // mutation or an attacker invoking a newly introduced capability.
    if (mcp && (f.unknown_tool_count > 0 || f.unknown_resource_count > 0 || f.unknown_prompt_count > 0) &&
        (tool || data || prompt))
        score += weights.get("chains.mcp_unknown_inventory");

    if (f.endpoint_drift_count > 0 && (tool || data || prompt))
        score += weights.get("chains.endpoint_drift_with_activity");

    if (f.inventory_change_count > 0 && (tool || data || provider || network))
        score += weights.get("chains.inventory_change_with_activity");

    // Prompt injection chain: injection -> tool call/abuse ->
    // provider/network. This is the highest-value application-layer chain.
    if (prompt && tool && (network || provider))
        score += weights.get("chains.prompt_tool_network");
    if (f.ordered_prompt_tool && f.ordered_tool_network)
        score += weights.get("chains.ordered_prompt_tool_network");

    // AI agent lateral movement. A lateral movement indicator becomes more
    // important when it is linked to an AI/MCP runtime or MCP HTTP session.
    if (lateral && (runtime || mcp) && (tool || data || network))
        score += weights.get("chains.lateral_ai_activity");
    if (f.ordered_shell_network && lateral)
        score += weights.get("chains.ordered_shell_lateral");

    // Multi-stage attack pipeline. Four or more stages plus tool activity is
    // treated as a pipeline even if no single signature is critical.
    if (stages >= 4 && (f.tool_call_count > 0 || f.tool_abuse_count > 0))
        score += weights.get("chains.multi_stage_tool_pipeline");
    if (f.ordered_llm_mcp_tool)
        score += weights.get("chains.ordered_llm_mcp_tool");

    // ---- REST API scoring ----
    if (f.rest_api_calls > 3) score += weights.get("signals.rest_api_calls");
    if (f.rest_auth_failures > 0) score += weights.get("signals.rest_auth_failures");
    if (f.rest_data_exfil > 0) score += weights.get("signals.rest_data_exfil");
    if (f.rest_rate_limit_hits > 3) score += weights.get("signals.rest_rate_limit");
    if (f.shadow_api_count > 0) score += weights.get("signals.shadow_api");
    if (f.rest_endpoint_probes > 20) score += weights.get("signals.rest_endpoint_probe");
    if (f.rest_ssrf > 0) score += weights.get("signals.rest_ssrf");
    if (f.rest_jwt_abuse > 1) score += weights.get("signals.rest_jwt_abuse");
    if (f.user_fraud_context_count > 0) score += weights.get("signals.user_fraud_context");

    const bool user_fraud_abuse =
        f.user_fraud_context_count > 0 &&
        (f.rest_auth_failures > 0 ||
         f.rest_jwt_abuse > 0 ||
         f.rest_rate_limit_hits > 0 ||
         f.rest_data_exfil > 0 ||
         f.a2a_task_access_count > 0 ||
         f.a2a_message_send_count > 0 ||
         f.tool_call_count > 0 ||
         f.tool_abuse_count > 0);

    if (user_fraud_abuse) score += weights.get("chains.user_fraud_abuse");
    if (f.user_fraud_context_count > 0 && f.rest_auth_failures > 0) score += weights.get("chains.user_fraud_auth_failure");
    if (f.user_fraud_context_count > 0 && f.rest_data_exfil > 0) score += weights.get("chains.user_fraud_data_exfil");

    // Cross-protocol: REST/MCP/A2A or REST + runtime = broader attack surface
    if (rest_api && mcp) score += weights.get("chains.rest_mcp");
    if (rest_api && a2a) score += weights.get("chains.rest_a2a");
    if (mcp && a2a) score += weights.get("chains.mcp_a2a");
    if (rest_api && runtime) score += weights.get("chains.rest_runtime");
    if (rest_api && (f.secret_access_count > 0 || f.rest_data_exfil > 0))
        score += weights.get("chains.rest_secret_or_exfil");
    if (f.rest_auth_failures > 0 && f.tool_call_count > 0)
        score += weights.get("chains.rest_auth_tool");

    // Temporal: REST activity close to runtime/MCP activity
    if (f.last_rest > 0 && f.last_runtime > 0 &&
        std::labs(f.last_rest - f.last_runtime) <= 30000)
        score += weights.get("temporal.rest_runtime");
    if (f.last_rest > 0 && f.last_http > 0 &&
        std::labs(f.last_rest - f.last_http) <= 30000)
        score += weights.get("temporal.rest_http");

    if (f.last_fraud_context > 0 && f.last_rest > 0 &&
        std::labs(f.last_fraud_context - f.last_rest) <= 30000 &&
        (f.rest_auth_failures > 0 || f.rest_data_exfil > 0 || f.rest_rate_limit_hits > 0))
        score += weights.get("temporal.fraud_rest_abuse");

    if (f.last_a2a > 0 && f.last_http > 0 &&
        std::labs(f.last_a2a - f.last_http) <= 30000)
        score += weights.get("temporal.a2a_http");

    if (f.last_a2a > 0 && f.last_runtime > 0 &&
        std::labs(f.last_a2a - f.last_runtime) <= 30000)
        score += weights.get("temporal.a2a_runtime");

    // Tight temporal relationships.
    if (f.last_runtime > 0 && f.last_http > 0 &&
        std::labs(f.last_runtime - f.last_http) <= 30000)
        score += weights.get("temporal.runtime_http");

    if (f.last_prompt > 0 && f.last_tool > 0 &&
        std::labs(f.last_prompt - f.last_tool) <= 30000)
        score += weights.get("temporal.prompt_tool");

    if (f.last_ipc > 0 && f.last_tls > 0 &&
        std::labs(f.last_ipc - f.last_tls) <= 30000)
        score += weights.get("temporal.ipc_tls");

    if (f.last_inventory > 0 && f.last_unknown_object > 0 &&
        std::labs(f.last_inventory - f.last_unknown_object) <= 30000)
        score += weights.get("temporal.inventory_unknown");

    if (f.last_corporate_data > 0 && f.provider_usage_count > 0 &&
        ((f.last_net > 0 && std::labs(f.last_corporate_data - f.last_net) <= 30000) ||
         (f.last_tls > 0 && std::labs(f.last_corporate_data - f.last_tls) <= 30000)))
        score += weights.get("temporal.corporate_data_provider");

    if (f.last_corporate_data > 0 && f.last_ai_gateway > 0 &&
        std::labs(f.last_corporate_data - f.last_ai_gateway) <= 30000)
        score += weights.get("temporal.corporate_data_gateway");

    if (score > weights.get("base.max_score")) score = weights.get("base.max_score");

    // A chain made only of protocol/context evidence (AI gateway, ordinary
    // tool call, provider) must not become HIGH by addition alone.
    if (!hasThreatEvidence(f)) {
        const double high = weights.get("thresholds.high");
        const double cap = std::max(0.0, high - 0.001);
        if (score > cap) score = cap;
    }

    return score;
}

RiskLevel classify(double score) {

    const ScoringConfig& weights = scoringConfig();

    if (score >= weights.get("thresholds.critical")) return CRITICAL;
    if (score >= weights.get("thresholds.high")) return HIGH;
    if (score >= weights.get("thresholds.medium")) return MEDIUM;

    return LOW;
}

std::string describeFindingTitle(const Features& f) {
    // The title is derived from the strongest observed chain so the SIEM/SOC
    // receives an immediately actionable finding category instead of a generic
    // "AI activity" label.
    const bool runtime = (f.stage_mask & STAGE_RUNTIME) != 0;
    const bool mcp = (f.stage_mask & STAGE_MCP) != 0;
    const bool a2a = (f.stage_mask & STAGE_A2A) != 0;
    const bool rest_api = (f.stage_mask & STAGE_REST_API) != 0;
    const bool network = (f.stage_mask & STAGE_NETWORK) != 0;
    const bool provider = (f.stage_mask & STAGE_PROVIDER) != 0;
    const bool tool = (f.stage_mask & STAGE_TOOL) != 0;

    if (f.corporate_data_context_count > 0 && provider)
        return f.ai_gateway_context_count > 0
            ? "Corporate Data Sent Through AI Gateway"
            : "Corporate Data Sent to AI Provider";

    const bool user_fraud_abuse =
        f.user_fraud_context_count > 0 &&
        (f.rest_auth_failures > 0 ||
         f.rest_jwt_abuse > 0 ||
         f.rest_rate_limit_hits > 0 ||
         f.rest_data_exfil > 0 ||
         f.a2a_task_access_count > 0 ||
         f.a2a_message_send_count > 0 ||
         f.tool_call_count > 0 ||
         f.tool_abuse_count > 0);

    if (user_fraud_abuse)
        return "User Fraud Workflow Abuse";

    if (f.a2a_artifact_exfil_count > 0)
        return "A2A Artifact Exfiltration";

    if (f.a2a_push_notification_count > 0)
        return "A2A Push Notification Abuse";

    if (f.a2a_agent_card_change_count > 0)
        return "A2A Agent Card Drift";

    if (f.a2a_unknown_agent_count > 0)
        return "A2A Unknown Agent Activity";

    if (a2a && mcp && tool)
        return "A2A Delegation to MCP Tool Abuse";

    if (a2a && rest_api)
        return "Multi-Protocol API Attack (A2A + REST)";

    if (a2a && runtime && (network || provider))
        return "A2A Runtime + Network Correlation";

    if (f.rest_data_exfil > 0)
        return "REST API Data Exfiltration";

    if (f.rest_ssrf > 0)
        return "REST API SSRF Attack";

    if (f.rest_jwt_abuse > 0 || f.rest_auth_failures > 0)
        return "REST API Authentication Abuse";

    if (f.rest_rate_limit_hits > 10)
        return "REST API Rate Limit Abuse";

    if (f.rest_endpoint_probes > 10)
        return "REST API Endpoint Probing";

    if (rest_api && runtime)
        return "REST API + Runtime Correlation";

    if (rest_api && mcp)
        return "Multi-Protocol API Attack (REST + MCP)";

    if (f.lateral_movement_count > 0)
        return "AI Agent Lateral Movement";

    if (f.prompt_injection_count > 0 && (f.tool_call_count > 0 || f.tool_abuse_count > 0))
        return "Prompt Injection Chain";

    if (f.unknown_tool_count > 0 || f.unknown_resource_count > 0 || f.unknown_prompt_count > 0)
        return "MCP Inventory Drift Attack";

    if (f.inventory_change_count > 0 && (tool || network || provider))
        return "MCP Inventory Change Chain";

    if (f.endpoint_drift_count > 0)
        return "MCP Endpoint Drift";

    if (mcp && tool && runtime && (network || provider))
        return "MCP Chain Attack";

    if (f.tool_abuse_count > 0 || f.tool_call_count > 0)
        return "Tool Abuse";

    if (runtime && (network || provider))
        return "MCP Runtime + Network Correlation";

    if (f.mcp_http_count > 0)
        return "MCP over HTTP";

    if (f.a2a_http_count > 0)
        return "A2A over HTTP";

    if (f.provider_usage_count > 0)
        return "AI Provider Usage";

    if (popcount(f.stage_mask) >= 4)
        return "Multi-stage Attack Pipeline";

    return "Suspicious API/AI Activity";
}

std::string describeAttackChain(const Features& f) {
    const bool rest_api = (f.stage_mask & STAGE_REST_API) != 0;
    const bool mcp = (f.stage_mask & STAGE_MCP) != 0;
    const bool a2a = (f.stage_mask & STAGE_A2A) != 0;

    if (f.user_fraud_context_count > 0 &&
        (f.rest_auth_failures > 0 || f.rest_jwt_abuse > 0 || f.rest_rate_limit_hits > 0 ||
         f.rest_data_exfil > 0 || f.a2a_task_access_count > 0 || f.a2a_message_send_count > 0 ||
         f.tool_call_count > 0 || f.tool_abuse_count > 0))
        return "Fraud-sensitive user workflow touched by correlated API or agent abuse";

    if (f.corporate_data_context_count > 0 && f.ai_gateway_context_count > 0)
        return "Corporate data context was observed in traffic sent through an AI gateway";

    if (f.corporate_data_context_count > 0 && f.provider_usage_count > 0)
        return "Corporate data context was observed in traffic correlated with an external AI provider";

    if (a2a && mcp)
        return "A2A agent delegation correlated with MCP activity, suggesting cross-agent tool execution risk";

    if (a2a && rest_api)
        return "A2A agent activity correlated with REST API activity, suggesting cross-protocol data movement";

    if (f.a2a_artifact_exfil_count > 0)
        return "A2A task artifacts exposed external URLs or tokenized download locations";

    if (f.a2a_push_notification_count > 0)
        return "A2A push notification callback configuration observed during correlated agent activity";

    if (rest_api && mcp)
        return "REST API and MCP activity correlated across timeline, suggesting multi-protocol attack";

    if (f.rest_data_exfil > 0)
        return "REST API data exfiltration detected with correlated runtime/network evidence";

    if (f.rest_auth_failures > 0)
        return "REST API authentication bypass attempts correlated across endpoints";

    if (f.ordered_prompt_tool && f.ordered_tool_network)
        return "LLM/MCP prompt injection led to tool execution and network activity";

    if (f.lateral_movement_count > 0 && f.ordered_shell_network)
        return "AI/MCP tool execution led to shell/network activity and lateral movement";

    if (f.unknown_tool_count > 0 || f.unknown_resource_count > 0 || f.unknown_prompt_count > 0)
        return "MCP traffic referenced tools/resources/prompts absent from the Alertflex inventory";

    if (f.inventory_change_count > 0)
        return "MCP inventory changed during a correlated tool/data/provider activity window";

    if (f.endpoint_drift_count > 0)
        return "MCP traffic reached an endpoint not present in the Alertflex inventory";

    if (f.ordered_llm_mcp_tool)
        return "LLM/provider context reached MCP and triggered tool execution";

    // Check if timeline has linked events (graph connectivity)
    int links = 0;
    for (const auto& ev : f.timeline)
        if (ev.linked_to >= 0) links++;
    if (links >= 2)
        return "Causally-linked API/AI events reconstructed across timeline";

    return "API/AI activity correlated across timeline evidence";
}

