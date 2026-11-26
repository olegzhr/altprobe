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

#ifndef TRACE_H
#define TRACE_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/lockfree/spsc_queue.hpp>

#include "source.h"
#include "filter.h"   // TraceCondition, TracePattern
#include "detection.h"
#include "trace_config.h"
#include <optional>

// ==============================
// TRACING - pattern matching and export of observed event chains
// ==============================
//
// The trace pattern model matches a chain of normalized events for one agent
// inside a bounded `window_sec`. It can require several conditions, a minimum
// event count and optionally strict order.
//
// The trace model keeps the raw facts instead:
//
//   1. proxy.cpp normalizes every observed request into a TraceEvent,
//      stamps it with the resolved agent_key (auth key, otherwise source IP)
//      and pushes it onto q_proxy_trace.
//   2. Trace::Go() drains that queue into an indexed TracePool (TTL +
//      cooldown, not a FIFO), then asks whether any configured pattern is
//      now satisfied across the *whole chain* of events belonging to that
//      agent - across tracks, not per request.
//   3. On a match Trace builds one OTLP/JSON ExportTraceServiceRequest and
//      durably queues it for Alertflex. Every observed span is independently
//      queued for OpenSearch, whether a trigger matches or not. External mode
//      consumes durably staged OTLP rather than the local proxy queue;
//      the pool is never drained by anyone else.
//
// This is deliberately not an OCSF Detection Finding: a trace reports what
// happened ("this agent did these things"), it does not decide that it was
// an attack. API Guard and the correlator analyze incoming sensor content
// separately. OtlpReceiver implements the external OTLP input transports.

// -------------------------------------------------------------
// Agent identity
// -------------------------------------------------------------
// Identity is resolved by the gateway: auth key when present, otherwise the
// observed source IP. Trace code only carries the resolved key.

// -------------------------------------------------------------
// TraceEvent - raw facts, no signals
// -------------------------------------------------------------

struct TraceEvent {
    // Original external OTLP resource/scope/span, with original identifiers.
    std::string external_otlp;
    std::string source = "proxy";
    std::string identity_source = "unknown";
    std::string trust_tier = "unknown";
    bool request_missing = false;
    bool response_missing = false;
    std::string transport;
    std::string application_protocol;
    std::string operation_state = "completed";
    int operation_status = 0;
    bool request_redacted = false;
    bool response_redacted = false;
    long        ts = 0;             // milliseconds
    std::string agent_key;
    std::string request_id;
    std::string session_id;
    std::string host_id;
    std::string track;              // "HTTP" / "MCP" / "A2A" / "SECURITY"

    std::string src_ip;
    std::string dst_ip;
    int         dst_port = 0;
    std::string http_method;
    std::string url;
    std::string mcp_method;
    std::string user_agent;
    std::string request_body;
    std::string response_body;
    int         status = 0;
    long        duration_ms = 0;    // for the eventual OTel span
    std::string span_kind;          // "tool" / "llm" / "a2a" / "http"

    // Body hygiene metadata (see processBody()): the stored body is
    // sanitized and truncated, these tell the consumer how much was lost.
    bool        request_truncated = false;
    size_t      request_original_size = 0;
    bool        response_truncated = false;
    size_t      response_original_size = 0;

    // Pool bookkeeping.
    uint64_t    id = 0;
    bool        matched = false;
    long        matched_at_ms = 0;
};

// -------------------------------------------------------------
// Body hygiene: sanitize -> validate -> truncate -> mark
// -------------------------------------------------------------

struct BodyLimits {
    size_t request_max  = 16 * 1024;
    size_t response_max = 16 * 1024;
    size_t url_max      = 2  * 1024;
    size_t ua_max       = 512;
    size_t mcp_method_max = 128;
    size_t key_max      = 512;
};

struct ProcessedBody {
    std::string value;              // sanitized + truncated
    bool        truncated = false;
    size_t      original_size = 0;
};

// Per-track limits (LLM prompts, tool listings and A2A payloads have very
// different natural sizes).
BodyLimits limitsFor(const std::string& track, const std::string& url);

// Strips obvious secrets (Bearer tokens, JSON api_key/token/password/...,
// PEM private keys) before truncation, so a secret near the cut boundary
// cannot survive by luck.
std::string sanitizeSecrets(const std::string& body);

// True when the payload looks like binary (NUL / control bytes) and should
// be replaced with a small placeholder rather than logged.
bool isBinaryBody(const std::string& s);

// Sanitizes, then truncates to max_size, marking truncation and the
// original size. `is_json` enables a bracket-aware cut when possible.
ProcessedBody processBody(const std::string& raw, size_t max_size, bool is_json);

// Plain truncation for scalar identity fields (url, user agent, session id).
std::string truncateField(const std::string& value, size_t max_size);

// -------------------------------------------------------------
// TracePool - indexed storage with TTL, not a queue
// -------------------------------------------------------------

class TracePool {
public:
    TracePool(size_t max_size, int ttl_sec, int cooldown_sec);

    void store(const TraceEvent& e);
    // reference_ms sets the recency floor (events older than
    // reference_ms - window_sec are excluded), defaulting to "now" when
    // omitted. The upper bound is wall-clock time: delayed sensor events
    // must not exclude newer observations already stored in the pool.
    std::vector<TraceEvent> getByAgent(const std::string& agent_key, int window_sec, long reference_ms = 0);
    void markMatched(const std::vector<TraceEvent>& chain);
    void evict();

private:
    size_t max_size_;
    int    ttl_sec_;
    int    cooldown_sec_;

    std::mutex mtx_;

    std::unordered_map<uint64_t, TraceEvent> events_;
    std::unordered_map<std::string, std::deque<uint64_t>> index_agent_;
    std::multimap<long, uint64_t> timeline_;

    uint64_t next_id_ = 1;

    void removeFromIndexes(const TraceEvent& e);
    void evictOldest();
};

// -------------------------------------------------------------
// Trace - chain collector and sole writer to Alertflex
// -------------------------------------------------------------

class Trace : public Source {
public:
    Trace();

    virtual bool Open() {
        if (traceConfig().mode == "off") {
            source_status = false;
            if (log_debug) SysLog((char*)"[Trace] disabled by configuration");
        }
        return source_status;
    }
    virtual bool Go();

private:
    friend struct TraceIntegrationTest;
    std::vector<TracePattern> patterns_;
    TracePool                 pool_;

    // last emission per "agent_key|pattern_id", for cooldown suppression.
    std::unordered_map<std::string, long> last_trace_emit_;
    std::unordered_map<std::string, uint64_t> last_relevant_id_;
    uint64_t last_patterns_version_ = 0;
    std::optional<TraceEvent> pending_;
    bool pending_stored_ = false;
    size_t pending_sink_ = 0;
    std::string incoming_id_;
    size_t incoming_span_ = 0, incoming_sink_ = 0;
    bool incoming_stored_ = false;

    void loadPatterns();
    bool checkChains(const TraceEvent& te);
    std::string observationJson(const TraceEvent& event);
    bool recentlyEmitted(const std::string& agent_key,
                         const std::string& pattern_id,
                         long now_ms, int cooldown_sec);
    void pruneEmitState(long now_ms);

    std::string buildTraceJson(
        const std::string& agent_key,
        const std::vector<TraceEvent>& chain,
        const TracePattern& pattern,
        long fired_at_ms);
};

extern Trace trace;

// One SPSC queue per producing source module. Drained exclusively by
// Trace::Go().
extern boost::lockfree::spsc_queue<TraceEvent> q_proxy_trace;
extern boost::lockfree::spsc_queue<TraceEvent> q_suricata_trace;


bool enqueueTraceEvent(
    boost::lockfree::spsc_queue<TraceEvent>& queue,
    const TraceEvent& e,
    const char* source_name);

#endif /* TRACE_H */
