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

#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <optional>
using std::string;
using std::vector;

// ==============================
// ENDPOINT MODEL
// ==============================
class Endpoint {
public:
    string path;
    string method;
    string type;
    string pipeline;
    int logbody;
    bool authorizationReady = false;
    bool accessApproved = false;
    string blockStatus = "active";
    string piiMode = "none";        // none | block | redact (from Alertflex endpoint)
    bool attachmentsAllowed = true;
    string status;
    int apicalls;
    
    Endpoint() {
        Reset();
    }
    
    void Reset() {
        path.clear();
        method.clear();
        type.clear();
        pipeline = "indef";
        logbody = 0;
        authorizationReady = false;
        accessApproved = false;
        blockStatus = "active";
        piiMode = "none";
        attachmentsAllowed = true;
        status.clear();
        apicalls = 0;
    }
};

// ==============================
// MCP MODELS
// ==============================
struct McpTool {
    string name;
    string description;
    string endpointPath;
    string inputSchema;
    string inputSchemaKey; // Typed, order-independent comparison key.
    bool hasInputSchema = false;
    bool hasDescription = false;
    string createdAt;
    string lastChanged;
};

struct McpResource {
    string uri;
    string name;
    string description;
    string mimeType;
    string endpointPath;
    string createdAt;
    string lastChanged;
    bool hasName = false;
    bool hasDescription = false;
    bool hasMimeType = false;
};

struct McpPrompt {
    string name;
    string description;
    string template_str;
    string argumentsKey;
    bool hasArguments = false;
    bool hasDescription = false;
    bool hasTemplate = false;
    string endpointPath;
    string createdAt;
    string lastChanged;
};

// ==============================
// TRACE PATTERNS
// ==============================
// Replaces the old per-event "Trigger" model. Instead of matching a single
// request body/url in isolation, a pattern describes a *chain* of events
// that belong to the same agent (see trace.h). Patterns are delivered
// through the same inventory channel as a top-level "patterns" array
// alongside "endpoints"/"mcp_tools"/etc.
//
// The old single-string Trigger payload is intentionally not supported here:
// Alertflex now publishes only canonical TracePattern objects.
struct TraceEvent;   // defined in trace.h

struct TraceCondition {
    string track;          // "HTTP" / "MCP" / "A2A" / "SECURITY"; empty = any
    string url_contains;
    string http_method;
    string mcp_method;
    string body_contains;
    int    status_eq = -1; // < 0 = ignore status
    bool   case_sensitive = true;

    bool matches(const TraceEvent& e) const;

    // True when the condition constrains nothing. Such conditions would match
    // every event, so the parser drops them instead of accepting a pattern
    // that accidentally fires on everything.
    bool isEmpty() const {
        return track.empty() && url_contains.empty() && http_method.empty()
            && mcp_method.empty() && body_contains.empty() && status_eq < 0;
    }
};

struct TracePattern {
    string id;
    string source = "*";       // proxy / otel / *
    string track = "*";        // "HTTP" / "MCP" / "A2A" / "SECURITY" / "*"
    int    window_sec = 300;   // tracing window (seconds)
    int    min_events = 2;
    int    cooldown_sec = 60;  // suppress re-emission of the same chain
    int    pattern_severity = 1;

    vector<TraceCondition> conditions;
    bool order_strict = false;

    bool appliesTo(const TraceEvent& e) const;
    bool matches(const vector<TraceEvent>& chain) const;
};

// ==============================
// CLIENT AGENT DECISIONS
// ==============================

struct InventoryAgent {
    std::optional<int64_t> keyExpiresAt; // UTC epoch milliseconds; nullopt = no expiry.
    string keyId, keyHash, keyStatus;
    string id;
    string name;
    string ip; // Observed address, never an enforcement identity.
    string version;
    string jsonRpc;
    string assetName;
    uint64_t apiCalls = 0;
    string blockStatus;
    string blockIncidentId;
    string blockReason;
    uint64_t blockedAt = 0;
    bool autoBlockEnabled = false;
    string bindingAssetName;
    string correlationUid;
    uint64_t createdAt = 0;
    uint64_t lastObserved = 0;
    string consumerGroupId;
    int riskScore = 0;
    std::optional<uint64_t> tokensUsedToday;
};

// ==============================
// INVENTORY STRUCTURE
// ==============================
struct DiscoveryTarget {
    string type, path, method, state;
    bool alerted = false;
    string route_template;
};

struct ConsumerGroupEndpoint {
    string protocol = "mcp";
    string method;
    string path;
    string tool;
    string action = "allow";
    int priority = 100;
};

struct ConsumerGroup {
    string id;
    string name;
    bool enabled = true;
    string policyMode = "allow_list";
    uint64_t maxTokensPerDay = 0;
    int riskScoreThreshold = 0;
    uint64_t version = 0;
    vector<ConsumerGroupEndpoint> endpoints;
};

struct PolicyInventory {
    bool agentAuthPresent = false;
    bool requireAgentKey = false;
    bool requireAgentGroup = false;
    int64_t tokenUsageValidUntil = 0;
    string accessPolicyRevision;
    vector<DiscoveryTarget> discovery_targets;
    vector<Endpoint> endpoints;
    vector<InventoryAgent> agents;
    vector<ConsumerGroup> consumer_groups;
    bool targetDecisionsPresent = false;
    bool agentsPresent = false;
    vector<McpTool> mcp_tools;
    vector<McpResource> mcp_resources;
    vector<McpPrompt> mcp_prompts;
    vector<TracePattern> patterns;
    uint64_t version = 0;
    std::chrono::steady_clock::time_point fetchedAt{};
};

