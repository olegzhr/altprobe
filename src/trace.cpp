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

#include "trace.h"
#include "helpers.h"
#include "trace_delivery.h"
#include "sinks.h"
#include "otlp.h"
#include "bounded_json.h"
#include "json_wire.h"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <algorithm>
#include <cctype>
#include <functional>
#include <iomanip>
#include <limits>
#include <regex>
#include <sstream>
#include <set>
#include <utility>
#include <unistd.h>

// -------------------------------------------------------------
// proxy -> trace queue
// -------------------------------------------------------------

boost::lockfree::spsc_queue<TraceEvent> q_proxy_trace{4096};
boost::lockfree::spsc_queue<TraceEvent> q_suricata_trace{4096};

static std::atomic<uint64_t> dropped_trace_events{0};

bool enqueueTraceEvent(
    boost::lockfree::spsc_queue<TraceEvent>& queue,
    const TraceEvent& e,
    const char* source_name
) {
    if (queue.push(e))
        return true;

    uint64_t dropped = ++dropped_trace_events;
    if (dropped == 1 || dropped % 100 == 0) {
        std::string msg = "[Trace] dropped event from ";
        msg.append(source_name ? source_name : "unknown");
        msg.append(": queue full, total_dropped=");
        msg.append(std::to_string(dropped));
        CObject::SysLog((char*)msg.c_str());
    }
    return false;
}

// -------------------------------------------------------------
// Time helper
// -------------------------------------------------------------

static long nowMs() {
    return (long)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string lowerStr(const std::string& v) {
    std::string r = v;
    std::transform(r.begin(), r.end(), r.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

static std::string trimCopy(const std::string& v) {
    size_t begin = 0;
    while (begin < v.size() && std::isspace((unsigned char)v[begin])) ++begin;

    size_t end = v.size();
    while (end > begin && std::isspace((unsigned char)v[end - 1])) --end;

    return v.substr(begin, end - begin);
}

static bool sameToken(const std::string& left, const std::string& right) {
    return lowerStr(trimCopy(left)) == lowerStr(trimCopy(right));
}

// -------------------------------------------------------------
// Agent identity
// -------------------------------------------------------------
// Identity is resolved by the gateway: auth key first, source IP otherwise.

// -------------------------------------------------------------
// TraceCondition (implemented here: needs the complete TraceEvent)
// -------------------------------------------------------------

static bool containsValue(const std::string& haystack,
                          const std::string& needle,
                          bool case_sensitive) {
    if (needle.empty()) return true;
    if (case_sensitive)
        return haystack.find(needle) != std::string::npos;
    return lowerStr(haystack).find(lowerStr(needle)) != std::string::npos;
}

static std::string extractMcpToolName(const std::string& body) {
    if (body.empty()) return "";
    try {
        boost::property_tree::ptree pt;
        std::istringstream iss(body);
        boost::property_tree::read_json(iss, pt);
        if (pt.get<std::string>("method", "") != "tools/call") return "";
        return pt.get<std::string>("params.name", "");
    } catch (...) {
        return "";
    }
}

static const std::set<std::string>& sensitiveToolNames() {
    static const std::set<std::string> names = {
        "exec", "execute", "execute_command", "run_command", "shell", "bash",
        "read_file", "write_file", "delete_file", "http_request", "curl",
        "fetch_url", "send_email", "read_secret", "get_secret", "get_secrets",
    };
    return names;
}

bool TraceCondition::matches(const TraceEvent& e) const {
    if (!track.empty() && !sameToken(e.track, track)) return false;

    if (!url_contains.empty() &&
        !containsValue(e.url, url_contains, case_sensitive)) return false;

    if (!http_method.empty() && !sameToken(e.http_method, http_method)) return false;
    if (!mcp_method.empty() && !sameToken(e.mcp_method, mcp_method)) return false;

    if (!body_contains.empty()) {
        std::string body = e.request_body;
        body.append(" ");
        body.append(e.response_body);
        if (!containsValue(body, body_contains, case_sensitive)) return false;
    }

    if (status_eq >= 0 && e.status != status_eq) return false;
    return true;
}

// -------------------------------------------------------------
// TracePattern
// -------------------------------------------------------------

bool TracePattern::appliesTo(const TraceEvent& e) const {
    if (source != "*" && !sameToken(source, e.source)) return false;
    if (trimCopy(track) != "*" && !sameToken(track, e.track)) return false;
    if (conditions.empty()) return true;

    for (const auto& c : conditions) {
        if (c.matches(e)) return true;
    }
    return false;
}

bool TracePattern::matches(const std::vector<TraceEvent>& chain) const {
    if ((int)chain.size() < min_events) return false;
    if (conditions.empty()) return true;

    if (order_strict) {
        size_t idx = 0;
        for (const auto& cond : conditions) {
            bool found = false;
            while (idx < chain.size()) {
                if (cond.matches(chain[idx])) { found = true; ++idx; break; }
                ++idx;
            }
            if (!found) return false;
        }
        return true;
    }

    for (const auto& cond : conditions) {
        bool found = false;
        for (const auto& e : chain) {
            if (cond.matches(e)) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

// -------------------------------------------------------------
// TracePool
// -------------------------------------------------------------

TracePool::TracePool(size_t max_size, int ttl_sec, int cooldown_sec)
    : max_size_(max_size), ttl_sec_(ttl_sec), cooldown_sec_(cooldown_sec) {}

void TracePool::store(const TraceEvent& e_in) {
    std::lock_guard<std::mutex> lk(mtx_);

    if (max_size_ == 0)
        return;
    if (!e_in.external_otlp.empty()) {
        auto previous = index_agent_.find(e_in.agent_key);
        if (previous != index_agent_.end()) for (auto id : previous->second) {
            const auto& e = events_.at(id);
            if (e.session_id == e_in.session_id && e.request_id == e_in.request_id) return;
        }
    }

    while (events_.size() >= max_size_)
        evictOldest();

    TraceEvent e = e_in;
    e.id = next_id_++;
    e.matched = false;

    events_[e.id] = e;

    if (!e.agent_key.empty())
        index_agent_[e.agent_key].push_back(e.id);

    timeline_.insert(std::make_pair(e.ts, e.id));
}

std::vector<TraceEvent> TracePool::getByAgent(
    const std::string& agent_key, int window_sec, long reference_ms)
{
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<TraceEvent> out;

    auto it = index_agent_.find(agent_key);
    if (it == index_agent_.end()) return out;

    long anchor = reference_ms > 0 ? reference_ms : nowMs();
    long cutoff = anchor - (long)window_sec * 1000;

    // Late sensor events may have earlier timestamps than already-pooled siblings.
    // Bound the chain by wall-clock time and reject future-dated observations.
    long now = nowMs();

    for (uint64_t id : it->second) {
        auto eit = events_.find(id);
        if (eit == events_.end()) continue;
        if (eit->second.ts < cutoff) continue;
        if (eit->second.ts > now) continue;
        out.push_back(eit->second);
    }

    std::sort(out.begin(), out.end(),
              [](const TraceEvent& a, const TraceEvent& b){ return a.ts != b.ts ? a.ts < b.ts : a.id < b.id; });
    return out;
}

void TracePool::markMatched(const std::vector<TraceEvent>& chain) {
    std::lock_guard<std::mutex> lk(mtx_);
    long ts = nowMs();

    for (const auto& c : chain) {
        auto it = events_.find(c.id);
        if (it == events_.end()) continue;
        it->second.matched = true;
        it->second.matched_at_ms = ts;
    }
}

void TracePool::evict() {
    std::lock_guard<std::mutex> lk(mtx_);
    long ts = nowMs();

    for (auto tit = timeline_.begin(); tit != timeline_.end(); ) {
        if (tit->first + (long)ttl_sec_ * 1000 >= ts)
            break;

        uint64_t id = tit->second;
        auto it = events_.find(id);
        if (it == events_.end()) {
            tit = timeline_.erase(tit);
            continue;
        }

        TraceEvent& e = it->second;
        bool expired = (ts - e.ts) > (long)ttl_sec_ * 1000;
        if (!expired) break;

        if (e.matched) {
            bool cooldown_done =
                (ts - e.matched_at_ms) > (long)cooldown_sec_ * 1000;
            if (!cooldown_done) {
                ++tit;
                continue;
            }
        }

        removeFromIndexes(e);
        events_.erase(id);
        tit = timeline_.erase(tit);
    }
}

void TracePool::removeFromIndexes(const TraceEvent& e) {
    if (!e.agent_key.empty()) {
        auto it = index_agent_.find(e.agent_key);
        if (it != index_agent_.end()) {
            auto& dq = it->second;
            dq.erase(std::remove(dq.begin(), dq.end(), e.id), dq.end());
            if (dq.empty()) index_agent_.erase(it);
        }
    }

}

void TracePool::evictOldest() {
    if (timeline_.empty()) return;
    auto tit = timeline_.begin();
    uint64_t id = tit->second;
    auto it = events_.find(id);
    if (it != events_.end()) {
        removeFromIndexes(it->second);
        events_.erase(it);
    }
    timeline_.erase(tit);
}

// -------------------------------------------------------------
// Body hygiene
// -------------------------------------------------------------

std::string sanitizeSecrets(const std::string& body) {
    if (body.empty()) return body;

    std::string out = body;

    static const std::regex re_bearer(
        R"((Bearer\s+)[A-Za-z0-9\-._~+/]+=*)",
        std::regex::icase);
    out = std::regex_replace(out, re_bearer, "$1[REDACTED]");

    static const std::regex re_kv(
        R"kv("(api[_-]?key|token|password|secret|authorization)"\s*:\s*"[^"]*")kv",
        std::regex::icase);
    out = std::regex_replace(out, re_kv, "\"$1\":\"[REDACTED]\"");

    static const std::regex re_ssh(
        R"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)");
    out = std::regex_replace(out, re_ssh, "[REDACTED_PRIVATE_KEY]");

    return out;
}

bool isBinaryBody(const std::string& s) {
    for (char c : s) {
        unsigned char u = (unsigned char)c;
        if (u == 0) return true;
        if (u < 0x09) return true;
        if (u > 0x0D && u < 0x20) return true;
    }
    return false;
}

// Best-effort truncation that keeps the result parseable when the original
// was a JSON object/array: cut right after the last closing bracket that
// fits, otherwise fall back to a raw cut (the caller has already marked the
// body as truncated, so the consumer knows it may be invalid JSON).
static std::string truncateJsonSafe(const std::string& s, size_t max_size) {
    if (s.size() <= max_size) return s;

    size_t cut = max_size;   // exclusive boundary
    while (cut > 0) {
        char c = s[cut - 1];
        if (c == '}' || c == ']') return s.substr(0, cut);
        --cut;
    }
    return s.substr(0, max_size);
}

ProcessedBody processBody(
    const std::string& raw, size_t max_size, bool is_json)
{
    ProcessedBody result;
    result.original_size = raw.size();
    if (raw.empty()) return result;

    if (isBinaryBody(raw)) {
        result.value = "[BINARY: " + std::to_string(raw.size()) + " bytes]";
        result.truncated = true;
        return result;
    }

    std::string sanitized = sanitizeSecrets(raw);

    if (sanitized.size() <= max_size) {
        result.value = std::move(sanitized);
        return result;
    }

    result.truncated = true;
    result.value = is_json
        ? truncateJsonSafe(sanitized, max_size)
        : sanitized.substr(0, max_size);
    return result;
}

std::string truncateField(const std::string& value, size_t max_size) {
    if (max_size == 0 || value.size() <= max_size) return value;
    return value.substr(0, max_size);
}

static std::string unixNanoString(long unix_ms) {
    long long ns = (long long)unix_ms * 1000000LL;
    return std::to_string(ns);
}

static std::string hexIdFromSeed(const std::string& seed, size_t chars) {
    std::hash<std::string> hasher;
    std::string out;
    uint64_t salt = 0;

    while (out.size() < chars) {
        uint64_t v = (uint64_t)hasher(seed + "|" + std::to_string(salt++));
        std::ostringstream chunk;
        chunk << std::hex << std::setw(16) << std::setfill('0') << v;
        out.append(chunk.str());
    }

    std::string id = out.substr(0, chars);
    bool non_zero = false;
    for (char c : id) {
        if (c != '0') {
            non_zero = true;
            break;
        }
    }
    if (!non_zero && !id.empty())
        id[id.size() - 1] = '1';
    return id;
}

static void appendAttrPrefix(std::string& json, bool& first) {
    if (!first) json.append(",");
    first = false;
}

static void appendStringAttr(std::string& json, bool& first,
                             const std::string& key,
                             const std::string& value) {
    appendAttrPrefix(json, first);
    json.append("{\"key\":\"");
    json.append(escapeJsonString(key));
    json.append("\",\"value\":{\"stringValue\":\"");
    json.append(escapeJsonString(value));
    json.append("\"}}");
}

static void appendIntAttr(std::string& json, bool& first,
                          const std::string& key, long long value) {
    appendAttrPrefix(json, first);
    json.append("{\"key\":\"");
    json.append(escapeJsonString(key));
    json.append("\",\"value\":{\"intValue\":\"");
    json.append(std::to_string(value));
    json.append("\"}}");
}

static void appendBoolAttr(std::string& json, bool& first,
                           const std::string& key, bool value) {
    appendAttrPrefix(json, first);
    json.append("{\"key\":\"");
    json.append(escapeJsonString(key));
    json.append("\",\"value\":{\"boolValue\":");
    json.append(value ? "true" : "false");
    json.append("}}");
}

static void appendDoubleAttr(std::string& json, bool& first,
                             const std::string& key, double value) {
    appendAttrPrefix(json, first);
    json.append("{\"key\":\"");
    json.append(escapeJsonString(key));
    json.append("\",\"value\":{\"doubleValue\":");
    std::ostringstream ss;
    ss << std::setprecision(12) << value;
    json.append(ss.str());
    json.append("}}");
}

static int toOtelSpanKind(const std::string& span_kind) {
    if (span_kind == "llm") return 3;   // SPAN_KIND_CLIENT
    return 2;                           // SPAN_KIND_SERVER
}

static bool isGenAiEvent(const TraceEvent& e) {
    std::string url = lowerStr(e.url);
    return e.span_kind == "llm" ||
           url.find("/v1/messages") != std::string::npos ||
           url.find("/v1/chat/completions") != std::string::npos ||
           url.find("/v1/responses") != std::string::npos ||
           url.find("/v1/completions") != std::string::npos ||
           url.find("/v1/embeddings") != std::string::npos ||
           url.find(":generatecontent") != std::string::npos;
}

static std::string inferGenAiProvider(const std::string& url_raw) {
    std::string url = lowerStr(url_raw);
    if (url.find("anthropic") != std::string::npos ||
        url.find("/v1/messages") != std::string::npos)
        return "anthropic";
    if (url.find("azure") != std::string::npos &&
        url.find("openai") != std::string::npos)
        return "azure.ai.openai";
    if (url.find("api.openai.com") != std::string::npos ||
        url.find("/v1/chat/completions") != std::string::npos ||
        url.find("/v1/responses") != std::string::npos ||
        url.find("/v1/completions") != std::string::npos)
        return "openai";
    if (url.find("generativelanguage.googleapis.com") != std::string::npos)
        return "gcp.gemini";
    if (url.find("aiplatform.googleapis.com") != std::string::npos)
        return "gcp.vertex_ai";
    return "";
}

static std::string inferGenAiOperation(const std::string& url_raw) {
    std::string url = lowerStr(url_raw);
    if (url.find("/v1/embeddings") != std::string::npos)
        return "embeddings";
    if (url.find("/v1/completions") != std::string::npos &&
        url.find("/v1/chat/completions") == std::string::npos)
        return "text_completion";
    if (url.find(":generatecontent") != std::string::npos)
        return "generate_content";
    return "chat";
}

static std::string spanNameForEvent(const TraceEvent& e) {
    if (e.track == "SECURITY")
        return e.mcp_method.empty() ? "Security finding" : "Security " + e.mcp_method;
    if (e.track == "MCP")
        return e.mcp_method.empty() ? "MCP request" : "MCP " + e.mcp_method;
    if (e.track == "A2A")
        return e.mcp_method.empty() ? "A2A request" : "A2A " + e.mcp_method;
    if (isGenAiEvent(e))
        return "GenAI " + inferGenAiOperation(e.url);
    if (!e.http_method.empty())
        return e.http_method + " " + truncateField(e.url, 128);
    return "HTTP request";
}

struct GenAiMetadata {
    std::string provider;
    std::string operation;
    std::string request_model;
    std::string response_model;
    std::string output_type;
    long long request_max_input_tokens = -1;
    long long request_max_output_tokens = -1;
    long long usage_input_tokens = -1;
    long long usage_output_tokens = -1;
    double temperature = 0.0;
    double top_p = 0.0;
    double top_k = 0.0;
    bool has_temperature = false;
    bool has_top_p = false;
    bool has_top_k = false;
    bool stream = false;
    bool has_stream = false;
};

static bool readJsonTree(const std::string& body, boost::property_tree::ptree& pt) {
    if (body.empty()) return false;
    try {
        std::istringstream iss(body);
        boost::property_tree::read_json(iss, pt);
        return true;
    } catch (...) {
        return false;
    }
}

static std::string jsonStringAt(const boost::property_tree::ptree& pt,
                                const std::string& key) {
    auto value = pt.get_optional<std::string>(key);
    return value ? *value : "";
}

static long long jsonIntAt(const boost::property_tree::ptree& pt,
                           const std::string& key) {
    auto value = pt.get_optional<long long>(key);
    return value ? *value : -1;
}

static bool jsonDoubleAt(const boost::property_tree::ptree& pt,
                         const std::string& key,
                         double& out) {
    auto value = pt.get_optional<double>(key);
    if (!value) return false;
    out = *value;
    return true;
}

static bool jsonBoolAt(const boost::property_tree::ptree& pt,
                       const std::string& key,
                       bool& out) {
    auto value = pt.get_optional<bool>(key);
    if (!value) return false;
    out = *value;
    return true;
}

static GenAiMetadata collectGenAiMetadata(const TraceEvent& e) {
    GenAiMetadata meta;
    meta.provider = inferGenAiProvider(e.url);
    meta.operation = inferGenAiOperation(e.url);

    boost::property_tree::ptree req;
    if (readJsonTree(e.request_body, req)) {
        meta.request_model = jsonStringAt(req, "model");
        meta.request_max_input_tokens = jsonIntAt(req, "max_input_tokens");
        meta.request_max_output_tokens = jsonIntAt(req, "max_output_tokens");
        if (meta.request_max_output_tokens < 0)
            meta.request_max_output_tokens = jsonIntAt(req, "max_completion_tokens");
        if (meta.request_max_output_tokens < 0)
            meta.request_max_output_tokens = jsonIntAt(req, "max_tokens");

        meta.has_temperature = jsonDoubleAt(req, "temperature", meta.temperature);
        meta.has_top_p = jsonDoubleAt(req, "top_p", meta.top_p);
        meta.has_top_k = jsonDoubleAt(req, "top_k", meta.top_k);
        meta.has_stream = jsonBoolAt(req, "stream", meta.stream);

        std::string response_type = jsonStringAt(req, "response_format.type");
        if (response_type.find("json") != std::string::npos)
            meta.output_type = "json";
        else if (!response_type.empty())
            meta.output_type = "text";
    }

    boost::property_tree::ptree resp;
    if (readJsonTree(e.response_body, resp)) {
        meta.response_model = jsonStringAt(resp, "model");
        meta.usage_input_tokens = jsonIntAt(resp, "usage.input_tokens");
        if (meta.usage_input_tokens < 0)
            meta.usage_input_tokens = jsonIntAt(resp, "usage.prompt_tokens");
        meta.usage_output_tokens = jsonIntAt(resp, "usage.output_tokens");
        if (meta.usage_output_tokens < 0)
            meta.usage_output_tokens = jsonIntAt(resp, "usage.completion_tokens");
    }

    if (meta.response_model.empty())
        meta.response_model = meta.request_model;
    if (meta.output_type.empty())
        meta.output_type = "text";

    return meta;
}

BodyLimits limitsFor(const std::string& track, const std::string& url) {
    BodyLimits l;
    if (track == "SECURITY") {
        l.request_max  = 8192;
        l.response_max = 1024;
        return l;
    }
    if (track == "MCP" && url.find("/tools/list") != std::string::npos) {
        l.request_max  = 4096;
        l.response_max = 65536;
        return l;
    }
    if (url.find("/v1/messages") != std::string::npos) {
        l.request_max  = 32768;
        l.response_max = 32768;
        return l;
    }
    if (track == "MCP") {
        l.request_max  = 16384;
        l.response_max = 16384;
        return l;
    }
    if (track == "A2A") {
        l.request_max  = 16384;
        l.response_max = 8192;
        return l;
    }
    l.request_max  = 8192;
    l.response_max = 8192;
    return l;
}

// -------------------------------------------------------------
// Trace
// -------------------------------------------------------------

Trace trace;

Trace::Trace()
    : pool_(100000, 300, 60)
{
    // Force the first Go() to load patterns. Doing it here would touch the
    // inventory (and its mutex) during static initialization, before the
    // filter module is guaranteed to be constructed.
    last_patterns_version_ = std::numeric_limits<uint64_t>::max();
}

void Trace::loadPatterns() {
    patterns_ = Filter::getPatterns();

    // TODO(P3 freshness): patterns are latched, not TTL'd - if ctrl becomes
    // unreachable the last delivered set stays active forever. Consider an
    // expiry here when/if ctrl availability must drop triggers automatically.
    if (patterns_.empty() && !Filter::patternsManaged()) {
        // Fallback so a fresh install still produces something useful
        // before alertflex-ctrl delivers its first pattern set.
        TracePattern p;
        p.id = "mcp_heavy_tool_usage";
        p.track = "MCP";
        p.window_sec = 300;
        p.min_events = 10;
        p.cooldown_sec = 60;
        p.pattern_severity = 3;

        TraceCondition c;
        c.track = "MCP";
        c.mcp_method = "tools/call";
        p.conditions.push_back(c);

        patterns_.push_back(p);
    }
}

bool Trace::recentlyEmitted(
    const std::string& agent_key, const std::string& pattern_id,
    long ts, int cooldown_sec)
{
    if (cooldown_sec <= 0) return false;

    auto it = last_trace_emit_.find(agent_key + "|" + pattern_id);
    if (it == last_trace_emit_.end()) return false;
    return (ts - it->second) < (long)cooldown_sec * 1000;
}

void Trace::pruneEmitState(long ts) {
    const long retention_ms = 3600L * 1000L;
    for (auto it = last_trace_emit_.begin(); it != last_trace_emit_.end(); ) {
        if (ts - it->second > retention_ms) {
            last_relevant_id_.erase(it->first);
            it = last_trace_emit_.erase(it);
        }
        else ++it;
    }
}

bool Trace::checkChains(const TraceEvent& te) {
    if (patterns_.empty() || !af_enable) return true;
    bool durable = true;

    // The selected mode feeds local observations or normalized external spans.
    const std::string stream_key = te.source + ":" + te.agent_key;

    long ts = nowMs();

    for (const auto& p : patterns_) {
        if (p.source != "*" && !sameToken(p.source, te.source)) continue;

        auto chain = pool_.getByAgent(te.agent_key, p.window_sec, te.ts);
        bool relevant = false;
        uint64_t relevant_id = 0;
        for (const auto& e : chain) {
            if (p.appliesTo(e)) {
                relevant = true;
                relevant_id = std::max(relevant_id, e.id);
            }
        }
        if (!relevant || !p.matches(chain)) continue;
        const std::string emission_key = stream_key + "|" + p.id;
        // Repeated sensor observations must not re-emit the same matched chain.
        auto last = last_relevant_id_.find(emission_key);
        if (last != last_relevant_id_.end() && relevant_id <= last->second) continue;
        if (recentlyEmitted(stream_key, p.id, ts, p.cooldown_sec)) continue;

        // Stable event time survives retries/restarts; body and dedup tag never change.
        long fired_at = te.ts;
        std::string trace_json = te.external_otlp.empty() ? buildTraceJson(te.agent_key, chain, p, fired_at)
            : externalTriggeredTrace(chain, p, te.agent_key, fired_at);

        if (log_debug) {
            SysLog((char*)"Trace: emitting:");
            SysLog((char*)trace_json.c_str());
        }

        if (!traceDelivery.alertflex(trace_json)) { durable = false; continue; }

        pool_.markMatched(chain);
        last_trace_emit_[emission_key] = ts;
        last_relevant_id_[emission_key] = relevant_id;
    }
    return durable;
}

std::string Trace::buildTraceJson(
    const std::string& agent_key,
    const std::vector<TraceEvent>& chain,
    const TracePattern& pattern,
    long fired_at_ms)
{
    std::set<std::string> tracks;
    std::set<std::string> sources;
    std::set<std::string> identity_sources;
    std::set<std::string> trust_tiers;
    for (const auto& e : chain) {
        tracks.insert(e.track);
        sources.insert(e.source);
        identity_sources.insert(e.identity_source);
        trust_tiers.insert(e.trust_tier);
    }

    int mcp_calls = 0, a2a_messages = 0, llm_requests = 0;
    int exec_calls = 0, file_reads = 0;
    std::set<std::string> sensitive_tools;

    for (const auto& e : chain) {
        if (e.track == "MCP") {
            mcp_calls++;
            std::string tool = lowerStr(extractMcpToolName(e.request_body));
            if (!tool.empty()) {
                if (tool == "read_file")
                    file_reads++;
                if (tool.find("exec") != std::string::npos ||
                    tool == "run_command" || tool == "shell" || tool == "bash")
                    exec_calls++;
                if (sensitiveToolNames().count(tool))
                    sensitive_tools.insert(tool);
            }
        }
        if (e.track == "A2A")  a2a_messages++;
        if (e.track == "HTTP" && e.url.find("/v1/messages") != std::string::npos)
            llm_requests++;
    }

    long chain_start = chain.empty() ? fired_at_ms : chain.front().ts;
    long chain_end   = chain.empty() ? fired_at_ms : chain.back().ts;
    if (chain_end < chain_start)
        chain_end = chain_start;

    std::string tracks_joined;
    for (const auto& t : tracks) {
        if (!tracks_joined.empty())
            tracks_joined.append(",");
        tracks_joined.append(t);
    }

    std::string sensitive_tools_joined;
    for (const auto& t : sensitive_tools) {
        if (!sensitive_tools_joined.empty())
            sensitive_tools_joined.append(",");
        sensitive_tools_joined.append(t);
    }

    std::string trace_seed = agent_key + "|" + pattern.id + "|" + std::to_string(fired_at_ms);
    std::string trace_id = hexIdFromSeed(trace_seed, 32);
    std::string root_span_id = hexIdFromSeed(trace_seed + "|root", 16);

    // OTLP/JSON ExportTraceServiceRequest. Field names follow protobuf JSON
    // lowerCamelCase and trace/span ids are hex strings.
    std::string json;
    json.append("{\"resourceSpans\":[{\"resource\":{\"attributes\":[");
    {
        bool first = true;
        appendStringAttr(json, first, "service.name", "altprobe");
        appendStringAttr(json, first, "service.instance.id", CObject::asset_name);
        appendStringAttr(json, first, "host.name", CObject::host_name);
        appendStringAttr(json, first, "alertflex.asset.name", CObject::asset_name);
        appendStringAttr(json, first, "alertflex.project.id", CObject::project_id);
    }
    json.append("]},\"scopeSpans\":[{\"scope\":{\"name\":\"altprobe.trace\",\"version\":\"1.0\"},\"spans\":[");

    json.append("{\"traceId\":\"");
    json.append(trace_id);
    json.append("\",\"spanId\":\"");
    json.append(root_span_id);
    json.append("\",\"name\":\"Alertflex trace ");
    json.append(escapeJsonString(pattern.id));
    json.append("\",\"kind\":1");
    json.append(",\"startTimeUnixNano\":\"");
    json.append(unixNanoString(chain_start));
    json.append("\",\"endTimeUnixNano\":\"");
    json.append(unixNanoString(chain_end > chain_start ? chain_end : chain_start + 1));
    json.append("\",\"attributes\":[");
    {
        bool first = true;
        appendStringAttr(json, first, "alertflex.trigger.id", pattern.id);
        appendStringAttr(json, first, "alertflex.trace.source",
            sources.size() == 1 ? *sources.begin() : "mixed");
        appendStringAttr(json, first, "alertflex.pattern.id", pattern.id);
        appendStringAttr(json, first, "alertflex.agent.key", agent_key);
        appendStringAttr(json, first, "alertflex.identity.source",
            identity_sources.size() == 1 ? *identity_sources.begin() : "mixed");
        appendStringAttr(json, first, "alertflex.trust_tier",
            trust_tiers.size() == 1 ? *trust_tiers.begin() : "mixed");
        appendStringAttr(json, first, "alertflex.track", pattern.track);
        appendIntAttr(json, first, "alertflex.pattern.severity", pattern.pattern_severity);
        appendIntAttr(json, first, "alertflex.trace.window_sec", pattern.window_sec);
        appendIntAttr(json, first, "alertflex.trace.min_events", pattern.min_events);
        appendBoolAttr(json, first, "alertflex.trace.order_strict", pattern.order_strict);
        appendIntAttr(json, first, "alertflex.trace.fired_at_unix_ms", fired_at_ms);
        appendIntAttr(json, first, "alertflex.trace.chain_start_unix_ms", chain_start);
        appendIntAttr(json, first, "alertflex.trace.chain_end_unix_ms", chain_end);
        appendIntAttr(json, first, "alertflex.trace.event_count", (long long)chain.size());
        appendStringAttr(json, first, "alertflex.trace.tracks", tracks_joined);
        appendIntAttr(json, first, "alertflex.summary.mcp_calls", mcp_calls);
        appendIntAttr(json, first, "alertflex.summary.a2a_messages", a2a_messages);
        appendIntAttr(json, first, "alertflex.summary.llm_requests", llm_requests);
        appendIntAttr(json, first, "alertflex.summary.exec_calls", exec_calls);
        appendIntAttr(json, first, "alertflex.summary.file_reads", file_reads);
        appendStringAttr(json, first, "alertflex.summary.sensitive_tools", sensitive_tools_joined);
    }
    json.append("],\"status\":{\"code\":1}}");

    for (size_t i = 0; i < chain.size(); ++i) {
        const auto& e = chain[i];
        long end_ts = e.ts + (e.duration_ms > 0 ? e.duration_ms : 1);
        std::string span_id = hexIdFromSeed(trace_seed + "|" + std::to_string(e.id) + "|" + std::to_string(i), 16);

        json.append(",{\"traceId\":\"");
        json.append(trace_id);
        json.append("\",\"spanId\":\"");
        json.append(span_id);
        json.append("\",\"parentSpanId\":\"");
        json.append(root_span_id);
        json.append("\",\"name\":\"");
        json.append(escapeJsonString(spanNameForEvent(e)));
        json.append("\",\"kind\":");
        json.append(std::to_string(toOtelSpanKind(e.span_kind)));
        json.append(",\"startTimeUnixNano\":\"");
        json.append(unixNanoString(e.ts));
        json.append("\",\"endTimeUnixNano\":\"");
        json.append(unixNanoString(end_ts));
        json.append("\",\"attributes\":[");
        {
            bool first = true;
            appendStringAttr(json, first, "alertflex.agent.key", agent_key);
            appendStringAttr(json, first, "alertflex.request.id", e.request_id);
            appendStringAttr(json, first, "alertflex.identity.source", e.identity_source);
            appendStringAttr(json, first, "alertflex.trust_tier", e.trust_tier);
            appendStringAttr(json, first, "alertflex.operation.state", e.operation_state);
            appendIntAttr(json, first, "alertflex.operation.status", e.operation_status);
            appendBoolAttr(json, first, "alertflex.request.body_missing", e.request_missing);
            appendBoolAttr(json, first, "alertflex.response.body_missing", e.response_missing);
            appendStringAttr(json, first, "session.id", e.session_id);
            appendStringAttr(json, first, "host.id", e.host_id);
            appendStringAttr(json, first, "alertflex.track", e.track);
            if (e.transport != "in_process") appendStringAttr(json, first, "http.request.method", e.http_method);
            appendStringAttr(json, first, "url.full", e.url);
            appendStringAttr(json, first, "rpc.method", e.mcp_method);
            appendStringAttr(json, first, "user_agent.original", e.user_agent);

            appendStringAttr(json, first, "source.address", e.src_ip);
            appendStringAttr(json, first, "server.address", e.dst_ip);
            appendIntAttr(json, first, "server.port", e.dst_port);
            appendIntAttr(json, first, "http.response.status_code", e.status);

            appendIntAttr(json, first, "alertflex.duration_ms", e.duration_ms);
            appendBoolAttr(json, first, "alertflex.request.truncated", e.request_truncated);
            appendIntAttr(json, first, "alertflex.request.original_size", (long long)e.request_original_size);
            appendBoolAttr(json, first, "alertflex.response.truncated", e.response_truncated);
            appendBoolAttr(json, first, "alertflex.request.redacted", e.request_redacted);
            appendBoolAttr(json, first, "alertflex.response.redacted", e.response_redacted);
            appendIntAttr(json, first, "alertflex.response.original_size", (long long)e.response_original_size);
            appendStringAttr(json, first, "alertflex.request.body", e.request_body);
            appendStringAttr(json, first, "alertflex.response.body", e.response_body);

            if (isGenAiEvent(e)) {
                GenAiMetadata gen_ai = collectGenAiMetadata(e);
                appendStringAttr(json, first, "gen_ai.operation.name", gen_ai.operation);
                if (!gen_ai.provider.empty())
                    appendStringAttr(json, first, "gen_ai.provider.name", gen_ai.provider);
                if (!gen_ai.request_model.empty())
                    appendStringAttr(json, first, "gen_ai.request.model", gen_ai.request_model);
                if (!gen_ai.response_model.empty())
                    appendStringAttr(json, first, "gen_ai.response.model", gen_ai.response_model);
                appendStringAttr(json, first, "gen_ai.output.type", gen_ai.output_type);
                if (gen_ai.request_max_input_tokens >= 0)
                    appendIntAttr(json, first, "gen_ai.request.max_input_tokens",
                                  gen_ai.request_max_input_tokens);
                if (gen_ai.request_max_output_tokens >= 0)
                    appendIntAttr(json, first, "gen_ai.request.max_output_tokens",
                                  gen_ai.request_max_output_tokens);
                if (gen_ai.has_temperature)
                    appendDoubleAttr(json, first, "gen_ai.request.temperature",
                                     gen_ai.temperature);
                if (gen_ai.has_top_p)
                    appendDoubleAttr(json, first, "gen_ai.request.top_p", gen_ai.top_p);
                if (gen_ai.has_top_k)
                    appendDoubleAttr(json, first, "gen_ai.request.top_k", gen_ai.top_k);
                if (gen_ai.has_stream)
                    appendBoolAttr(json, first, "gen_ai.request.stream", gen_ai.stream);
                if (gen_ai.usage_input_tokens >= 0)
                    appendIntAttr(json, first, "gen_ai.usage.input_tokens",
                                  gen_ai.usage_input_tokens);
                if (gen_ai.usage_output_tokens >= 0)
                    appendIntAttr(json, first, "gen_ai.usage.output_tokens",
                                  gen_ai.usage_output_tokens);
            }
        }
        json.append("],\"status\":{\"code\":");
        json.append(e.operation_status == 2 || e.status >= 400 ? "2" : (e.operation_state == "started" ? "0" : "1"));
        json.append("}}");
    }

    json.append("]}]}]}");
    return json;
}

bool Trace::Go() {
    uint64_t v = Filter::getInventoryVersion();
    if (v != last_patterns_version_) {
        loadPatterns();
        last_patterns_version_ = v;
    }

    if (traceConfig().mode == "internal") {
        while (source_status) {
            if (!pending_) {
                TraceEvent te;
                if (!q_proxy_trace.pop(te) && !q_suricata_trace.pop(te)) break;
                pending_ = std::move(te);
                pending_stored_ = false;
                pending_sink_ = 0;
            }
            if (!pending_stored_) {
                if (!traceDelivery.stageSinks(observationJson(*pending_), pending_sink_)) break;
                pool_.store(*pending_); pending_stored_ = true;
            }
            if (!checkChains(*pending_)) break;
            pending_.reset();
        }
    } else if (traceConfig().mode == "external") {
        auto ids = traceDelivery.incomingIds();
        const auto active = std::find(ids.begin(), ids.end(), incoming_id_);
        if (active != ids.end()) std::rotate(ids.begin(), active, active + 1);
        for (const auto& id : ids) {
            if (!source_status) break;
            if (incoming_id_ != id) {
                incoming_id_ = id;
                incoming_span_ = incoming_sink_ = 0;
                incoming_stored_ = false;
            }
            std::string body, error; OtlpRequest request;
            // Protobuf -> JSON may expand beyond the transport body limit.
            // This record was already validated and durably accepted by the receiver.
            if (!traceDelivery.readIncoming(id,body) || !decodeOtlp(body,true,request,error,33554432)) break;
            const auto events = externalTraceEvents(request);
            for (; source_status && incoming_span_ < events.size(); ++incoming_span_) {
                const auto& te = events[incoming_span_];
                if (!incoming_stored_) {
                    if (!traceDelivery.stageSinks(te.external_otlp, incoming_sink_)) break;
                    pool_.store(te);
                    incoming_stored_ = true;
                }
                if (!checkChains(te)) break;
                incoming_stored_ = false;
                incoming_sink_ = 0;
            }
            if (incoming_span_ != events.size() || !traceDelivery.finishIncoming(id)) break;
            incoming_id_.clear();
        }
    }

    pool_.evict();
    pruneEmitState(nowMs());

    usleep(GetGosleepInterval() * 60);
    return source_status;
}

std::string Trace::observationJson(const TraceEvent& event) {
    // Reuse the standard span/body hygiene builder, excluding the synthetic
    // trigger root: OpenSearch receives every observed span, matched or not.
    TracePattern observed; observed.id = "observation:" + event.request_id; observed.track = event.track;
    auto body = buildTraceJson(event.agent_key,{event},observed,event.ts);
    Json json;
    if (!parseBoundedJson(body,json,33554432,1048576)) throw std::runtime_error("observation serialization failed");
    for (auto& r:json.children) if(r.first=="resourceSpans") for(auto& resource:r.second.children)
        for(auto& s:resource.second.children) if(s.first=="scopeSpans") for(auto& scope:s.second.children)
            for(auto& a:scope.second.children) if(a.first=="spans" && a.second.children.size()>1) {
                a.second.children.erase(a.second.children.begin());
                auto& fields=a.second.children.front().second.children;
                fields.erase(std::remove_if(fields.begin(),fields.end(),[](const auto& f){return f.first=="parentSpanId";}),fields.end());
            }
    return wireJson(json);
}
