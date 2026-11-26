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

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "correlator.h"
#include "helpers.h"
#include "mitre.h"
#include "filter.h"
#include "trace.h"
#include "json_wire.h"
#include "inventory.h"

#include <atomic>
#include <algorithm>

boost::lockfree::spsc_queue<Event> q_suricata_correlator{4096};
boost::lockfree::spsc_queue<Event> q_proxy_correlator{4096};
boost::lockfree::spsc_queue<Event> q_modsec_correlator{4096};
boost::lockfree::spsc_queue<Event> q_llm_correlator{4096};

std::atomic<bool> incident_ready{false};
boost::lockfree::spsc_queue<IncidentEnvelope> q_finding_incident{512};

static std::atomic<uint64_t> dropped_correlator_events{0};

static long secondsToMillis(int seconds, int fallback_seconds) {
    if (seconds <= 0)
        seconds = fallback_seconds;

    return (long)seconds * 1000;
}

bool enqueueCorrelatorEvent(
    boost::lockfree::spsc_queue<Event>& queue,
    const Event& event,
    const char* source_name
) {
    Event normalized = event;
    normalizeEvent(normalized);
    if (queue.push(normalized))
        return true;

    uint64_t dropped = ++dropped_correlator_events;
    if (dropped == 1 || dropped % 100 == 0) {
        std::string msg = "[Correlator] dropped event from ";
        msg.append(source_name ? source_name : "unknown");
        msg.append(": input queue is full, total_dropped=");
        msg.append(std::to_string(dropped));
        CObject::SysLog((char*)msg.c_str());
    }

    return false;
}



static std::string jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size());

    for (char c : value) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"': out.append("\\\""); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default: out.push_back(c); break;
        }
    }

    return out;
}

static std::string firstNonEmptyValue(
    const std::string& a,
    const std::string& b,
    const std::string& c = "",
    const std::string& d = ""
) {
    if (!a.empty()) return a;
    if (!b.empty()) return b;
    if (!c.empty()) return c;
    return d;
}

static std::string apiOperationForEvent(const Event& e) {
    // Alertflex resolves endpoint risk by the same operation + concrete path
    // used by inventory. A bare "tools/call" loses the endpoint reference;
    // replacing it with POST instead would target a different inventory row.
    // Envoy uses '-' for an absent dynamic-metadata value, including ordinary
    // LLM/REST requests. It is not a JSON-RPC operation.
    const std::string mcp = e.mcp_method == "-" ? "" : e.mcp_method;
    const std::string a2a = e.a2a_operation == "-" ? "" : e.a2a_operation;
    const std::string method = firstNonEmptyValue(mcp, a2a, e.http_method);
    if (!method.empty() && !e.url.empty()) {
        Http http{};
        http.url = e.url;
        Inventory inventory;
        return method + " " + inventory.endpointPathForRequest(http, TYPE_REST);
    }
    // Non-HTTP/stdio findings have no route. Preserve their display operation
    // without inventing '/' and accidentally scoring an unrelated endpoint.
    if (!mcp.empty()) return mcp;
    if (!a2a.empty()) return a2a;
    if (!e.mcp_object_name.empty()) return e.mcp_object_name;
    if (!e.http_method.empty()) return e.http_method;
    return signalName(e.signal);
}

static std::string apiServiceForEvent(const Event& e) {
    if (!e.mcp_object_type.empty()) return "mcp_" + e.mcp_object_type;
    if (!e.a2a_agent_name.empty()) return e.a2a_agent_name;
    if (!e.provider.empty()) return e.provider;
    return "alertflex_correlator";
}

static std::string consumerNameForEvent(const Event& e, const std::string& key) {
    // Display name from the authenticated inventory record; the stable UID in
    // `key` remains the correlation identity and is only a last resort label.
    const auto name = firstNonEmptyValue(
        e.consumer_name,
        e.identity_name,
        e.a2a_agent_name,
        e.process
    );
    return name.empty() ? key : name;
}

std::string Correlator::resolveKey(const Event& e) {
    return makeKey(e);
}

static uint32_t threatMask(const Features& f) {
    // Ordinary protocol/tool activity must not consume the first alert for a
    // dangerous category, even when the score has already reached CRITICAL.
    uint32_t mask = 0;
    if (f.prompt_injection_count > 0) mask |= 1u << 0;
    if (f.tool_abuse_count > 0) mask |= 1u << 1;
    if (f.lateral_movement_count > 0) mask |= 1u << 2;
    if (f.inventory_change_count > 0) mask |= 1u << 3;
    if (f.endpoint_drift_count > 0) mask |= 1u << 4;
    if (f.unknown_tool_count > 0) mask |= 1u << 5;
    if (f.unknown_resource_count > 0) mask |= 1u << 6;
    if (f.unknown_prompt_count > 0) mask |= 1u << 7;
    return mask;
}

bool Correlator::shouldEmit(const std::string& key, long ts, RiskLevel risk, uint32_t threat_mask) {
    auto it = last_emit.find(key);
    if (it == last_emit.end() ||
        ts - it->second.ts >= secondsToMillis(CObject::alert_cooldown, 30))
        return true;

    // Suppress repeats, but publish escalation and newly observed threats.
    return risk > it->second.risk ||
        (threat_mask & ~it->second.threat_mask) != 0;
}

void Correlator::markEmit(const std::string& key, long ts, RiskLevel risk, uint32_t threat_mask) {
    auto& emitted = last_emit[key];
    if (emitted.ts == 0 ||
        ts - emitted.ts >= secondsToMillis(CObject::alert_cooldown, 30)) {
        emitted.ts = ts;
        emitted.risk = risk;
        emitted.threat_mask = threat_mask;
        return;
    }

    // Keep the published high-water marks during cooldown. Late events must
    // not move its timestamp backwards or make old threats look new again.
    emitted.ts = std::max(emitted.ts, ts);
    emitted.risk = std::max(emitted.risk, risk);
    emitted.threat_mask |= threat_mask;
}

void Correlator::cleanupEmitState(long now) {
    for (auto it = last_emit.begin(); it != last_emit.end(); ) {
        if (now - it->second.ts > secondsToMillis(CObject::alert_cooldown, 30)) {
            it = last_emit.erase(it);
        } else {
            ++it;
        }
    }
}

// ---- Main processing loop ----
bool Correlator::Go() {

    Event e;
    const long wall_now = eventTimeMillis(0);
    // Reclaim idle entities too. Each window is also expired before insertion,
    // so a returning identity cannot revive its previous threat state.
    if (wall_now - last_window_cleanup_ >= 1000) {
        for (auto it = state.begin(); it != state.end();) {
            if (!it->second.expire(wall_now, secondsToMillis(CObject::entity_ttl, 90))) it = state.erase(it);
            else ++it;
        }
        last_window_cleanup_ = wall_now;
    }
    
    auto correlateEvent = [&](Event event) {

        normalizeEvent(event);
        // All adapters use event time; old replayed telemetry must not revive
        // expired entity state or trigger automatic actions today.
        const long now = eventTimeMillis(0);
        if (event.ts > now + 60000 || now - event.ts > secondsToMillis(CObject::entity_ttl, 90)) return;

        processed_events++;
        auto k = resolveKey(event);
        auto& window = state[k];

        // Streaming update path:
        // 1. Fold the new event into the entity feature state.
        // 2. Score the full attack chain accumulated in the sliding window.
        window.add(event, now, secondsToMillis(CObject::entity_ttl, 90));
        const auto& f = window.features;

        double score = scoreAPI(f);
        RiskLevel r = classify(score);
        const uint32_t threat_mask = threatMask(f);

        // Emit only meaningful detections
        if (r >= HIGH && shouldEmit(k, event.ts, r, threat_mask)) {
            if (emitFinding(k, f, score, r, event)) {
                markEmit(k, event.ts, r, threat_mask);
            }
        }

        // lightweight periodic cleanup
        int cleanup_interval = CObject::cleanup_interval > 0 ? CObject::cleanup_interval : 100;
        if (processed_events % (uint64_t)cleanup_interval == 0) {
            cleanupEmitState(now);
        }
    };

    auto processEvent = [&](Event event) {
        if (!detection_enabled || event.signal == SIG_UNKNOWN) return;
        correlateEvent(event);
    };

    // Consume each single-producer queue separately. This keeps the queue type
    // safe while allowing Proxy, Modsec and LLM flows to feed the same engine
    // without multiple producers writing into one SPSC queue.
    for (size_t left = q_proxy_correlator.read_available(); left && q_proxy_correlator.pop(e); --left) {
        processEvent(e);
    }


    for (size_t left = q_modsec_correlator.read_available(); left && q_modsec_correlator.pop(e); --left) {
        processEvent(e);
    }
    for (size_t left = q_llm_correlator.read_available(); left && q_llm_correlator.pop(e); --left) {
        processEvent(e);
    }
    
    const long now = eventTimeMillis(0);
    for (size_t left = q_suricata_correlator.read_available(); left && q_suricata_correlator.pop(e); --left) {
        if (e.network_evidence == "ids_http") processEvent(e);
    }
    // Cleanup also runs while idle.
    cleanupEmitState(now);
    usleep(GetGosleepInterval()*60);
    
    return source_status;
}

// ==============================
// 10. OUTPUT (FINDING)
// ==============================
//
// Hook for OCSF / OpenSearch / Alertflex (API correlation findings)
//
bool Correlator::emitFinding(
    const std::string& key,
    const Features& f,
    double score,
    RiskLevel risk,
    const Event& e
) {
    try {

        std::string json;
        const std::string incident_id = boost::uuids::to_string(boost::uuids::random_generator()());

        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        std::string operation = apiOperationForEvent(e);
        std::string service_name = apiServiceForEvent(e);
        std::string consumer_name = consumerNameForEvent(e, key);

        // =============================
        // OCSF ROOT
        // =============================

        json.append("{");
        json.append("\"activity_id\":1");
        json.append(",\"activity_name\":\"Agent Correlation\"");
        json.append(",\"category_uid\":6");
        json.append(",\"category_name\":\"Application Activity\"");
        json.append(",\"class_uid\":6003,\"action_id\":1");
        json.append(",\"class_name\":\"API Activity\"");
        json.append(",\"type_uid\":600301");
        json.append(",\"status_id\":1");
        json.append(",\"status\":\"Success\"");

        // =============================
        // METADATA (STRICT OCSF)
        // =============================

        json.append(",\"metadata\":{");
        json.append("\"uid\":\"" + incident_id + "\",\"log_name\":\"alertflex_correlator\"");
        json.append(",\"log_provider\":\"Alertflex\"");
        json.append(",\"logged_time\":");
        json.append(std::to_string(ms));
        json.append(",\"version\":\"1.8.0\"");
        json.append(",\"product\":{\"name\":\"Alertflex Correlator\",\"vendor_name\":\"Alertflex\"}");
        json.append(",\"correlation_uid\":\"");
        json.append(jsonEscape(key));
        json.append("\"");
        json.append("}");

        // =============================
        // TIME
        // =============================

        json.append(",\"time\":");
        json.append(std::to_string(ms));

        json.append(",\"start_time\":");
        json.append(std::to_string(f.first_seen));

        json.append(",\"end_time\":");
        json.append(std::to_string(f.last_seen));

        // =============================
        // SEVERITY (OCSF STYLE)
        // =============================

        json.append(",");

        switch (risk) {
            case CRITICAL:
                json.append("\"severity_id\":4,\"severity\":\"Critical\"");
                break;
            case HIGH:
                json.append("\"severity_id\":3,\"severity\":\"High\"");
                break;
            case MEDIUM:
                json.append("\"severity_id\":2,\"severity\":\"Medium\"");
                break;
            default:
                json.append("\"severity_id\":1,\"severity\":\"Low\"");
        }

        // =============================
        // MESSAGE (FREE TEXT)
        // =============================

        json.append(",\"message\":\"Correlation detected for key=");
        json.append(jsonEscape(key));
        json.append(" score=");
        json.append(std::to_string(score));
        json.append("\"");

        // =============================
        // API ACTIVITY ENTITIES
        // =============================

        json.append(",\"actor\":{\"user\":{");
        json.append("\"uid\":\"");
        json.append(jsonEscape(key));
        json.append("\",\"name\":\"");
        json.append(jsonEscape(consumer_name));
        json.append("\",\"type_id\":99,\"type\":\"AI Agent\"");
        json.append("}");
        if (!e.session_id.empty()) {
            json.append(",\"session\":{\"uid\":\"");
            json.append(jsonEscape(e.session_id));
            json.append("\"}");
        }
        json.append("}");

        json.append(",\"api\":{");
        json.append("\"service\":{\"name\":\"");
        json.append(jsonEscape(service_name));
        json.append("\",\"version\":\"1.0.0\"}");
        json.append(",\"operation\":\"");
        json.append(jsonEscape(operation));
        json.append("\"");
        if (e.status > 0) {
            json.append(",\"response\":{\"code\":");
            json.append(std::to_string(e.status));
            json.append("}");
        }
        json.append("}");

        // =============================
        // CORE OCSF ENTITIES (IMPORTANT)
        // =============================

        if (e.protocol != "in_process") {
            json.append(",\"src_endpoint\":{");
            json.append("\"type_id\":99,\"name\":\"AI Agent Endpoint\"");
            if (!e.host_id.empty()) {
                json.append(",\"hostname\":\"");
                json.append(jsonEscape(e.host_id));
                json.append("\"");
            }
            json.append(",\"ip\":\"");
            json.append(jsonEscape(isValidIp(e.src_ip) ? e.src_ip : "0.0.0.0"));
            json.append("\"");
            if (e.src_port > 0) json.append(",\"port\":" + std::to_string(e.src_port));
            json.append("}");

            json.append(",\"dst_endpoint\":{");
            json.append("\"type_id\":1");
            if (!e.dst_ip.empty()) {
                json.append(",\"name\":\"");
                json.append(jsonEscape(e.dst_ip));
                json.append("\"");
            }
            json.append(",\"ip\":\"");
            json.append(jsonEscape(isValidIp(e.dst_ip) ? e.dst_ip : "0.0.0.0"));
            json.append("\"");
            if (e.dst_port > 0) {
                json.append(",\"port\":");
                json.append(std::to_string(e.dst_port));
            }
            json.append("}");

        }

        json.append(",\"process\":{");
        json.append("\"name\":\"");
        json.append(jsonEscape(e.process));
        json.append("\",\"pid\":");
        json.append(std::to_string(e.process_pid));
        json.append("}");

        if (e.protocol != "in_process") {
            json.append(",\"http_request\":{");
            // HTTP fields are sparse for network-only events and populated for
            // Proxy or Modsec HTTP events. Keeping them in the finding helps an
            // analyst inspect the API endpoint and request class without searching
            // the original logs first.
            json.append("\"method\":\"");
            json.append(jsonEscape(e.http_method));
            json.append("\",\"url\":\"");
            json.append(jsonEscape(e.url));
            json.append("\",\"user_agent\":\"");
            json.append(jsonEscape(e.user_agent));
            json.append("\"}");

        }

        // =============================
        // AOS-STYLE EXTENSION
        // =============================

        json.append(",\"osint\":[]");

        json.append(",\"trace\":{");
        json.append("\"uid\":\"");
        json.append(jsonEscape(key));
        json.append("\",\"span\":{\"uid\":\"");
        json.append(jsonEscape(std::to_string(ms)));
        json.append("\",\"start_time\":");
        json.append(std::to_string(f.first_seen));
        json.append(",\"end_time\":");
        json.append(std::to_string(f.last_seen));
        json.append("}}");

        json.append(",\"unmapped\":{\"aos\":{");
        json.append("\"finding\":{\"title\":\"");
        json.append(jsonEscape(describeFindingTitle(f)));
        json.append("\",\"uid\":\"");
        json.append(jsonEscape(key));
        json.append("\",\"confidence\":");
        json.append(std::to_string((int)(score * 100)));
        json.append("}");
        json.append(",\"context\":{\"agent\":{\"id\":\"");
        json.append(jsonEscape(key));
        json.append("\",\"name\":\"");
        json.append(jsonEscape(consumer_name));
        json.append("\",\"provider\":{\"name\":\"Alertflex\"}}");
        if (!e.session_id.empty()) {
            json.append(",\"session\":{\"id\":\"");
            json.append(jsonEscape(e.session_id));
            json.append("\"}");
        }
        json.append("}");
        json.append(",\"step\":{\"id\":\"");
        json.append(jsonEscape(std::to_string(ms)));
        json.append("\",\"type\":\"correlation\",\"operation\":{\"type\":\"agent_correlation\",\"name\":\"");
        json.append(jsonEscape(operation));
        json.append("\"}}");
        json.append(",\"source_event\":{\"provider\":\"");
        json.append(jsonEscape(e.provider));
        json.append("\",\"rule\":\"");
        json.append(jsonEscape(e.rule));
        json.append("\"}");
        json.append(",\"correlation\":{");

        json.append("\"score\":");
        json.append(std::to_string(score));

        json.append(",\"attack_chain\":{");
        json.append("\"summary\":\"");
        json.append(jsonEscape(describeAttackChain(f)));
        json.append("\",\"timeline\":[");

        for (size_t i = 0; i < f.timeline.size(); ++i) {
            const auto& ev = f.timeline[i];
            if (i > 0) json.append(",");
            json.append("{\"id\":");
            json.append(std::to_string(i));
            json.append(",\"time\":");
            json.append(std::to_string(ev.ts));
            json.append(",\"source\":\"");
            json.append(jsonEscape(sourceName(ev.source)));
            json.append("\",\"stage\":\"");
            json.append(jsonEscape(stageName(ev.stage)));
            json.append("\",\"signal\":\"");
            json.append(jsonEscape(signalName(ev.signal)));
            json.append("\",\"api_guard\":");
            json.append(buildApiGuardExplanationJson(ev.guard));
            if (!ev.llm_guard.status.empty()) json.append(",\"llm_guard\":" + buildLlmGuardExplanationJson(ev.llm_guard));
            json.append(",\"mitre_framework\":\"");
            json.append(jsonEscape(mitreFramework(ev.signal)));
            json.append("\",\"mitre_tactic\":\"");
            json.append(jsonEscape(mitreTactic(ev.signal)));
            json.append("\",\"mitre_technique_id\":\"");
            json.append(jsonEscape(mitreTechniqueId(ev.signal)));
            json.append("\",\"mitre_technique\":\"");
            json.append(jsonEscape(mitreTechniqueName(ev.signal)));
            json.append("\",\"summary\":\"");
            json.append(jsonEscape(ev.summary));
            json.append("\",\"process\":\"");
            json.append(jsonEscape(ev.process));
            json.append("\",\"src_ip\":\"");
            json.append(jsonEscape(isValidIp(ev.src_ip) ? ev.src_ip : "0.0.0.0"));
            json.append("\",\"dst_ip\":\"");
            json.append(jsonEscape(isValidIp(ev.dst_ip) ? ev.dst_ip : "0.0.0.0"));
            json.append("\",\"url\":\"");
            json.append(jsonEscape(ev.url));
            json.append("\",\"sni\":\"");
            json.append(jsonEscape(ev.sni));
            json.append("\",\"session_id\":\"");
            json.append(jsonEscape(ev.session_id));
            if (!ev.trace_id.empty()) {
                json.append("\",\"trace_id\":\"");
                json.append(jsonEscape(ev.trace_id));
                json.append("\",\"span_id\":\"");
                json.append(jsonEscape(ev.span_id));
            }
            json.append("\",\"mcp_method\":\"");
            json.append(jsonEscape(ev.mcp_method));
            json.append("\",\"mcp_object_type\":\"");
            json.append(jsonEscape(ev.mcp_object_type));
            json.append("\",\"mcp_object_name\":\"");
            json.append(jsonEscape(ev.mcp_object_name));
            json.append("\",\"mcp_inventory_status\":\"");
            json.append(jsonEscape(ev.policy_inventory_status));
            json.append("\",\"mcp_inventory_version\":");
            json.append(std::to_string(ev.policy_inventory_version));
            json.append(",\"mcp_inventory_inspection_status\":\"" + jsonEscape(ev.policy_inventory_inspection_status) + "\"");
            json.append(",\"mcp_drifts\":" + buildMcpDriftsJson(ev.mcp_drifts));
            json.append(",\"a2a_operation\":\"");
            json.append(jsonEscape(ev.a2a_operation));
            json.append("\",\"a2a_agent_name\":\"");
            json.append(jsonEscape(ev.a2a_agent_name));
            json.append("\",\"a2a_skill_id\":\"");
            json.append(jsonEscape(ev.a2a_skill_id));
            json.append("\",\"a2a_task_id\":\"");
            json.append(jsonEscape(ev.a2a_task_id));
            json.append("\",\"a2a_task_state\":\"");
            json.append(jsonEscape(ev.a2a_task_state));
            json.append("\"");
            json.append(",\"linked_to\":");
            json.append(std::to_string(ev.linked_to));
            json.append(",\"link_type\":\"");
            json.append(jsonEscape(ev.link_type));
            json.append("\"");
            json.append("}");
        }

        json.append("]}");

        json.append(",\"features\":{");

        json.append("\"ipc_count\":");
        json.append(std::to_string(f.ipc_count));

        json.append(",\"ai_process\":");
        json.append(std::to_string(f.proc_ai_count));

        json.append(",\"net_connections\":");
        json.append(std::to_string(f.net_conn_count));

        json.append(",\"tls_burst\":");
        json.append(std::to_string(f.tls_burst));

        json.append(",\"small_requests\":");
        json.append(std::to_string(f.small_req));

        json.append(",\"ja3_hits\":");
        json.append(std::to_string(f.ja3_hits));

        json.append(",\"proc_behavior\":");
        json.append(std::to_string(f.proc_behavior_count));

        json.append(",\"llm_sni_hits\":");
        json.append(std::to_string(f.sni_llm_hits));

        json.append(",\"llm_dns_hits\":");
        json.append(std::to_string(f.dns_llm_hits));

        json.append(",\"llm_cert_hits\":");
        json.append(std::to_string(f.cert_llm_hits));

        json.append(",\"llm_asn_hits\":");
        json.append(std::to_string(f.asn_llm_hits));

        json.append(",\"long_tls_sessions\":");
        json.append(std::to_string(f.long_tls_sessions));

        json.append(",\"repetitive_tls_patterns\":");
        json.append(std::to_string(f.repetitive_tls_patterns));

        json.append(",\"anomaly_count\":");
        json.append(std::to_string(f.anomaly_count));

        json.append(",\"mcp_http\":");
        json.append(std::to_string(f.mcp_http_count));

        json.append(",\"tool_list\":");
        json.append(std::to_string(f.tool_list_count));

        json.append(",\"tool_call\":");
        json.append(std::to_string(f.tool_call_count));

        json.append(",\"resource_access\":");
        json.append(std::to_string(f.resource_access_count));

        json.append(",\"prompt_injection\":");
        json.append(std::to_string(f.prompt_injection_count));

        json.append(",\"tool_abuse\":");
        json.append(std::to_string(f.tool_abuse_count));

        json.append(",\"lateral_movement\":");
        json.append(std::to_string(f.lateral_movement_count));

        json.append(",\"secret_access\":");
        json.append(std::to_string(f.secret_access_count));

        json.append(",\"provider_usage\":");
        json.append(std::to_string(f.provider_usage_count));

        json.append(",\"inventory_discovery\":");
        json.append(std::to_string(f.inventory_discovery_count));

        json.append(",\"inventory_change\":");
        json.append(std::to_string(f.inventory_change_count));

        json.append(",\"unknown_tool\":");
        json.append(std::to_string(f.unknown_tool_count));

        json.append(",\"unknown_resource\":");
        json.append(std::to_string(f.unknown_resource_count));

        json.append(",\"unknown_prompt\":");
        json.append(std::to_string(f.unknown_prompt_count));

        json.append(",\"endpoint_drift\":");
        json.append(std::to_string(f.endpoint_drift_count));

        json.append(",\"prompt_access\":");
        json.append(std::to_string(f.prompt_access_count));

        json.append(",\"sampling_request\":");
        json.append(std::to_string(f.sampling_request_count));

        json.append(",\"elicitation_request\":");
        json.append(std::to_string(f.elicitation_request_count));

        json.append(",\"a2a_http\":");
        json.append(std::to_string(f.a2a_http_count));

        json.append(",\"a2a_agent_card\":");
        json.append(std::to_string(f.a2a_agent_card_count));

        json.append(",\"a2a_agent_card_change\":");
        json.append(std::to_string(f.a2a_agent_card_change_count));

        json.append(",\"a2a_message_send\":");
        json.append(std::to_string(f.a2a_message_send_count));

        json.append(",\"a2a_task_access\":");
        json.append(std::to_string(f.a2a_task_access_count));

        json.append(",\"a2a_task_cancel\":");
        json.append(std::to_string(f.a2a_task_cancel_count));

        json.append(",\"a2a_push_notification\":");
        json.append(std::to_string(f.a2a_push_notification_count));

        json.append(",\"a2a_artifact_exfil\":");
        json.append(std::to_string(f.a2a_artifact_exfil_count));

        json.append(",\"a2a_auth_required\":");
        json.append(std::to_string(f.a2a_auth_required_count));

        json.append(",\"a2a_unknown_agent\":");
        json.append(std::to_string(f.a2a_unknown_agent_count));

        json.append(",\"rest_api_calls\":");
        json.append(std::to_string(f.rest_api_calls));

        json.append(",\"rest_auth_failures\":");
        json.append(std::to_string(f.rest_auth_failures));

        json.append(",\"rest_data_exfil\":");
        json.append(std::to_string(f.rest_data_exfil));

        json.append(",\"rest_rate_limit_hits\":");
        json.append(std::to_string(f.rest_rate_limit_hits));

        json.append(",\"rest_endpoint_probes\":");
        json.append(std::to_string(f.rest_endpoint_probes));
        json.append(",\"shadow_api_count\":");
        json.append(std::to_string(f.shadow_api_count));

        json.append(",\"rest_ssrf\":");
        json.append(std::to_string(f.rest_ssrf));

        json.append(",\"rest_jwt_abuse\":");
        json.append(std::to_string(f.rest_jwt_abuse));

        json.append(",\"stage_mask\":");
        // stage_mask/source_mask are compact explainability fields. They let
        // downstream analytics reconstruct which chain phases and telemetry
        // sources contributed to the decision.
        json.append(std::to_string(f.stage_mask));

        json.append(",\"source_mask\":");
        json.append(std::to_string(f.source_mask));

        json.append("}}}}");
        json.append("}");

        // =============================
        // OUTPUT
        // =============================

        if (log_debug) {
            SysLog((char*)"OCSF API Activity correlation:");
            SysLog((char*)json.c_str());
        }

        // Enqueue before sink I/O: OpenSearch failure must not suppress incidents.
        bool queued = false;
        if (incident_enabled && incident_ready.load() && risk >= HIGH) {
            IncidentEnvelope incident;
            incident.id = incident_id;
            incident.body = "{\"schema_version\":\"1.0\",\"incident_id\":\"" + incident_id +
                "\",\"project_id\":\"" + jsonEscape(project_id) +
                "\",\"probe\":{\"asset_name\":\"" + jsonEscape(asset_name) +
                "\",\"hostname\":\"" + jsonEscape(host_name) + "\"},\"finding\":" + json + "}";
            if (incident.body.size() <= 262144) queued = q_finding_incident.push(incident);
            if (!queued) SysLog((char*)"[Correlator] incident not queued: incident queue full or payload exceeds 256 KiB");
        }
        int log_sinks_result = sk.sendOcsfToLogSinks(json, 6003, "indef", "correlator");
        if (log_sinks_result != 1)
            SysLog((char*)"[Correlator] finding log sink delivery failed");
        return queued || log_sinks_result == 1;
            
    } catch (const std::exception& ex) {
        SysLog((char*)ex.what());
        return false;
    }
}

