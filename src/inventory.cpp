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

#include "inventory.h"
#include "bounded_json.h"
#include <set>
#include <unordered_map>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <regex>
#include <sstream>
#include <boost/property_tree/json_parser.hpp>

bool Inventory::matchEndpoint(const Http& http, RequestType type, Endpoint& out_ep) {

    std::string path = endpointPathForRequest(http, type);
    std::string method = endpointMethodForRequest(http, type);
    std::string expected_type = (type == TYPE_MCP) ? "MCP" :
        ((type == TYPE_A2A) ? "A2A" :
        ((type == TYPE_REST) ? "REST" : ""));

    // =========================
    // MATCH
    // =========================
    std::vector<Endpoint> endpoints = Filter::getEndpoints();
    for (const auto& ep : endpoints) {
        bool type_matches = expected_type.empty() ||
            ep.type.empty() ||
            lowerCopy(ep.type) == lowerCopy(expected_type);

        if (ep.path == path && ep.method == method && type_matches) {
            out_ep = ep;
            return true;
        }
    }

    return false;
}







bool Inventory::isA2aTaskActivity(const Http& http, const Event& e) const {
    if (e.signal == SIG_A2A_TASK_ACCESS ||
        e.signal == SIG_A2A_TASK_CANCEL)
        return true;

    std::string operation = lowerCopy(e.a2a_operation);
    if (operation.empty())
        operation = lowerCopy(extractA2aOperation(http));

    if (operation.find("task_") == 0)
        return true;

    std::string method = lowerCopy(extractJsonRpcMethod(http.request_body));
    if (method.empty())
        method = lowerCopy(extractJsonRpcMethod(http.response_body));

    if (method.find("tasks/") == 0)
        return true;

    std::string joined = lowerCopy(
        http.url + " " +
        http.request_body + " " +
        http.response_body
    );

    if (joined.find("/tasks") != std::string::npos ||
        joined.find("\"taskid\"") != std::string::npos ||
        joined.find("\"task_id\"") != std::string::npos ||
        joined.find("task_state_") != std::string::npos)
        return true;

    if (joined.find("\"task\"") != std::string::npos &&
        (joined.find("\"status\"") != std::string::npos ||
         joined.find("\"artifacts\"") != std::string::npos))
        return true;

    return false;
}











bool Inventory::isMcpSignal(SignalType signal) const {
    switch (signal) {
        case SIG_MCP_IPC:
        case SIG_MCP_STDIO:
        case SIG_HTTP_PATTERN:
        case SIG_MCP_HTTP:
        case SIG_MCP_TOOL_LIST:
        case SIG_MCP_TOOL_CALL:
        case SIG_MCP_RESOURCE_ACCESS:
        case SIG_PROMPT_INJECTION:
        case SIG_TOOL_ABUSE:
        case SIG_LATERAL_MOVEMENT:
        case SIG_SECRET_ACCESS:
        case SIG_MCP_CHAIN_STAGE:
        case SIG_ATTACK_PIPELINE:
        case SIG_MCP_INVENTORY_DISCOVERY:
        case SIG_MCP_INVENTORY_CHANGE:
        case SIG_MCP_UNKNOWN_TOOL:
        case SIG_MCP_UNKNOWN_RESOURCE:
        case SIG_MCP_UNKNOWN_PROMPT:
        case SIG_MCP_ENDPOINT_DRIFT:
        case SIG_MCP_PROMPT_ACCESS:
        case SIG_MCP_SAMPLING_REQUEST:
        case SIG_MCP_ELICITATION_REQUEST:
            return true;
        default:
            return false;
    }
}

bool Inventory::canInventoryOverride(SignalType signal) const {
    switch (signal) {
        case SIG_UNKNOWN:
        case SIG_HTTP_PATTERN:
        case SIG_MCP_HTTP:
        case SIG_MCP_TOOL_LIST:
        case SIG_MCP_TOOL_CALL:
        case SIG_MCP_RESOURCE_ACCESS:
        case SIG_MCP_CHAIN_STAGE:
        case SIG_MCP_INVENTORY_DISCOVERY:
        case SIG_MCP_PROMPT_ACCESS:
        case SIG_MCP_ENDPOINT_DRIFT:
            return true;
        default:
            return false;
    }
}

bool Inventory::hasMcpDrift(const Event& e) const {
    if (!e.mcp_drifts.empty()) return true;
    switch (e.signal) {
        case SIG_MCP_INVENTORY_CHANGE:
        case SIG_MCP_ENDPOINT_DRIFT:
        case SIG_MCP_UNKNOWN_TOOL:
        case SIG_MCP_UNKNOWN_RESOURCE:
        case SIG_MCP_UNKNOWN_PROMPT:
            return true;
        default:
            return false;
    }
}

bool Inventory::shouldSendToAlertflex(
    RequestType type,
    bool endpoint_matched,
    const Endpoint& endpoint,
    const Event& e) const
{
    // Only REST, MCP, and A2A traffic participates in inventory ingestion control.
    // Unknown traffic can still be processed by the local pipeline, but it is
    // not a candidate for API discovery traffic sent to alertflex.
    if (type == TYPE_UNKNOWN)
        return false;

    // MCP drift is a higher-priority inventory signal. Even confirmed or
    // excluded endpoints must report drift because the changed tool/resource/
    // prompt surface is exactly what alertflex needs to reconcile.
    if (type == TYPE_MCP && hasMcpDrift(e))
        return true;

    if (type == TYPE_A2A && e.signal != SIG_UNKNOWN)
        return true;

    // If the endpoint is missing from the downloaded inventory snapshot, send
    // the full log so alertflex can create the discovery record with
    // apiState=unconfirmed.
    if (!endpoint_matched)
        return true;

    std::string status = lowerCopy(endpoint.status);

    // Confirmed and excluded endpoints are already known from the inventory
    // perspective. Their apiCalls still move through the lightweight counter
    // synchronization path, but the full request/response log is suppressed.
    if (status == "confirmed" || status == "excluded")
        return false;

    // The server controls discovery completion. Counters continue after the alert;
    // ordinary full logs stop once the server has acknowledged the target alert.
    if (status == "unconfirmed") {
        const auto snapshot = Filter::getInventory();
        const std::string target_method = type == TYPE_REST ? endpoint.method : "";
        const std::string route_template = normalizePath(endpoint.path, true);
        for (const auto& target : snapshot.discovery_targets)
            if (target.type == endpoint.type && target.method == target_method && target.path == endpoint.path)
                return !target.alerted && target.state == "unconfirmed";
        for (const auto& target : snapshot.discovery_targets)
            if (target.type == endpoint.type && target.method == target_method &&
                    !target.route_template.empty() && target.route_template == route_template)
                return !target.alerted && target.state == "unconfirmed";
        return true;
    }

    // Empty or unexpected status values are treated conservatively. Sending the
    // full log is safer than silently dropping a potentially new API surface
    // because an older service version returned an unknown state label.
    return true;
}









bool Inventory::endpointKnown(const PolicyInventory& inventory, const Event& e) const {
    if (e.url.empty() || e.url == "indef")
        return true;

    std::string httpMethod = lowerCopy(e.http_method);
    std::string mcpMethod = lowerCopy(e.mcp_method);

    for (const auto& ep : inventory.endpoints) {
        if (!sameEndpointPath(ep.path, e.url))
            continue;

        std::string epMethod = lowerCopy(ep.method);
        if (epMethod == httpMethod || epMethod == mcpMethod)
            return true;
    }

    return false;
}

bool Inventory::objectKnown(const PolicyInventory& inventory, const Event& e) const {
    if (e.mcp_object_name.empty())
        return true;

    std::string type = lowerCopy(e.mcp_object_type);
    const std::string& name = e.mcp_object_name;

    if (type == "tool") {
        for (const auto& tool : inventory.mcp_tools) {
            bool scopeMatches = tool.endpointPath.empty() || e.url.empty() ||
                sameEndpointPath(tool.endpointPath, e.url);
            if (scopeMatches && tool.name == name)
                return true;
        }
        return false;
    }

    if (type == "resource") {
        for (const auto& resource : inventory.mcp_resources) {
            bool scopeMatches = resource.endpointPath.empty() || e.url.empty() ||
                sameEndpointPath(resource.endpointPath, e.url);
            if (scopeMatches &&
                (resource.uri == name || resource.name == name))
                return true;
        }
        return false;
    }

    if (type == "prompt") {
        for (const auto& prompt : inventory.mcp_prompts) {
            bool scopeMatches = prompt.endpointPath.empty() || e.url.empty() ||
                sameEndpointPath(prompt.endpointPath, e.url);
            if (scopeMatches && prompt.name == name)
                return true;
        }
        return false;
    }

    return true;
}

void Inventory::enrich(Event& e, bool inspect_request) {
    if (!isMcpSignal(e.signal) && e.mcp_method.empty() &&
        e.application_protocol != "mcp" && e.request_body.empty() && e.response_body.empty())
        return;

    Json request;
    bool valid_request = e.request_body.empty() ||
        (parseBoundedJson(e.request_body, request) && request.kind == 'o' &&
         request.string("jsonrpc") == "2.0" && !request.string("method").empty() &&
         !request.get("result") && !request.get("error"));
    auto request_params = request.get("params");
    auto rpc_id = request.get("id");
    if ((request_params && request_params->kind != 'o' && request_params->kind != 'a') ||
        (rpc_id && rpc_id->kind != 's' && rpc_id->kind != 'd' && rpc_id->kind != 'n'))
        valid_request = false;
    if (!valid_request || e.request_truncated) {
        if (!isMcpSignal(e.signal) && e.mcp_method.empty() && e.application_protocol != "mcp") return;
        e.policy_inventory_inspection_status = e.request_truncated ? "truncated_request" : "invalid_request";
        return;
    }
    const std::string method = request.string("method").empty() ? e.mcp_method : request.string("method");
    if (method.empty()) return;
    // Generic JSON-RPC and A2A envelopes do not imply an MCP inventory surface.
    const bool mcp_method = method == "initialize" || method == "ping" ||
        method.rfind("tools/", 0) == 0 || method.rfind("resources/", 0) == 0 ||
        method.rfind("prompts/", 0) == 0 || method.rfind("roots/", 0) == 0 ||
        method.rfind("notifications/", 0) == 0 || method.rfind("sampling/", 0) == 0 ||
        method.rfind("elicitation/", 0) == 0 || method.rfind("logging/", 0) == 0 ||
        method.rfind("completion/", 0) == 0;
    if (e.application_protocol == "a2a" || (!mcp_method && e.application_protocol != "mcp")) return;
    e.mcp_method = method;
    auto add = [&](SignalType signal, const std::string& status,
                   const std::string& type, const std::string& name, const std::string& field) {
        size_t end = std::min(name.size(), size_t(512));
        if (end < name.size())
            while (end && (static_cast<unsigned char>(name[end]) & 0xc0) == 0x80) --end;
        const std::string display_name = name.substr(0, end);
        for (const auto& d : e.mcp_drifts)
            if (d.signal == signal && d.status == status && d.object_type == type &&
                d.object_name == display_name && d.field == field) return;
        if (e.mcp_drifts.size() >= 128) {
            e.policy_inventory_inspection_status = "drift_limit";
            return;
        }
        e.mcp_drifts.push_back({signal, status, type, display_name, field});
        if (e.policy_inventory_status.empty() || e.policy_inventory_status == "known_object")
            e.policy_inventory_status = status;
        if (canInventoryOverride(e.signal)) e.signal = signal;
    };
    if (inspect_request && (method == "notifications/tools/list_changed" ||
        method == "notifications/resources/list_changed" ||
        method == "notifications/prompts/list_changed" ||
        method == "notifications/roots/list_changed"))
        add(SIG_MCP_INVENTORY_CHANGE, "inventory_change_notification", "", "", "");

    PolicyInventory inventory = Filter::getInventory();
    if (inventory.version == 0) {
        e.policy_inventory_inspection_status = "no_inventory";
        return;
    }

    e.policy_inventory_version = inventory.version;

    bool hasInventoryData =
        !inventory.endpoints.empty() ||
        !inventory.mcp_tools.empty() ||
        !inventory.mcp_resources.empty() ||
        !inventory.mcp_prompts.empty();

    if (!hasInventoryData) {
        e.policy_inventory_inspection_status = "empty_inventory";
        return;
    }
    e.policy_inventory_inspection_status = "complete";

    if (inspect_request && !inventory.endpoints.empty() && !endpointKnown(inventory, e)) {
        add(SIG_MCP_ENDPOINT_DRIFT, "unknown_endpoint", "endpoint", e.url, "");
    }

    if (e.mcp_object_name.empty() && request_params && request_params->kind == 'o') {
        if (method == "tools/call") {
            e.mcp_object_type = "tool";
            e.mcp_object_name = request_params->string("name");
        } else if (method == "prompts/get") {
            e.mcp_object_type = "prompt";
            e.mcp_object_name = request_params->string("name");
        } else if (method == "resources/read" || method == "resources/subscribe" || method == "resources/unsubscribe") {
            e.mcp_object_type = "resource";
            e.mcp_object_name = request_params->string("uri");
        }
    }
    if (inspect_request && !e.mcp_object_name.empty()) {
        if (objectKnown(inventory, e)) {
            if (e.policy_inventory_status.empty())
                e.policy_inventory_status = "known_object";
        } else {
            const std::string type = lowerCopy(e.mcp_object_type);
            if (type == "tool") add(SIG_MCP_UNKNOWN_TOOL, "unknown_tool", type, e.mcp_object_name, "");
            if (type == "resource") add(SIG_MCP_UNKNOWN_RESOURCE, "unknown_resource", type, e.mcp_object_name, "");
            if (type == "prompt") add(SIG_MCP_UNKNOWN_PROMPT, "unknown_prompt", type, e.mcp_object_name, "");
        }
    }

    const bool listing = method == "tools/list" || method == "resources/list" || method == "prompts/list";
    const bool prompt_get = method == "prompts/get";
    if ((!listing && !prompt_get) || e.response_body.empty()) return;
    if (e.response_truncated || e.response_missing) {
        e.policy_inventory_inspection_status = "incomplete_response";
        return;
    }
    Json response;
    if (!parseBoundedJson(e.response_body, response) || response.kind != 'o' ||
        response.string("jsonrpc") != "2.0") {
        e.policy_inventory_inspection_status = "invalid_response";
        return;
    }
    if (response.get("error")) return;
    auto response_id = response.get("id");
    auto request_id = request.get("id");
    if (!response_id || (response_id->kind != 's' && response_id->kind != 'd' && response_id->kind != 'n') ||
        (request_id && canonicalJson(*request_id) != canonicalJson(*response_id))) {
        e.policy_inventory_inspection_status = "unpaired_response";
        return;
    }
    auto result = response.get("result");
    if (!result || result->kind != 'o') { e.policy_inventory_inspection_status = "invalid_result"; return; }
    auto scope = [&](const std::string& path) {
        return path.empty() || (!e.url.empty() && sameEndpointPath(path, e.url));
    };
    auto changed = [&](const std::string& type, const std::string& name, const std::string& field) {
        add(SIG_MCP_INVENTORY_CHANGE, "object_changed", type, name, field);
    };
    if (prompt_get) {
        auto observed = result->get("template");
        // Only compare an explicitly supplied template. Rendered messages can
        // legitimately vary with arguments and are not a template snapshot.
        if (observed && observed->kind == 's')
            for (const auto& p : inventory.mcp_prompts)
                if (p.name == e.mcp_object_name && scope(p.endpointPath) &&
                    p.hasTemplate && p.template_str != observed->text)
                    changed("prompt", p.name, "template");
        return;
    }
    const std::string key = method == "tools/list" ? "tools" : method == "resources/list" ? "resources" : "prompts";
    const std::string type = method == "tools/list" ? "tool" : method == "resources/list" ? "resource" : "prompt";
    auto objects = result->get(key);
    if (!objects || objects->kind != 'a') { e.policy_inventory_inspection_status = "invalid_list"; return; }
    std::unordered_map<std::string, const McpTool*> tools;
    std::unordered_map<std::string, const McpResource*> resources;
    std::unordered_map<std::string, const McpPrompt*> prompts;
    // Endpoint-specific definitions take priority over wildcard definitions.
    if (type == "tool") for (const auto& t : inventory.mcp_tools)
        if (scope(t.endpointPath) && (!tools.count(t.name) || !t.endpointPath.empty())) tools[t.name] = &t;
    if (type == "resource") for (const auto& r : inventory.mcp_resources)
        if (scope(r.endpointPath) && (!resources.count(r.uri) || !r.endpointPath.empty())) resources[r.uri] = &r;
    if (type == "prompt") for (const auto& p : inventory.mcp_prompts)
        if (scope(p.endpointPath) && (!prompts.count(p.name) || !p.endpointPath.empty())) prompts[p.name] = &p;
    std::set<std::string> names;
    // Validate the whole page before accepting it as a complete list.
    for (const auto& item : objects->children) {
        const Json& object = item.second;
        const std::string name = object.string(type == "resource" ? "uri" : "name");
        if (object.kind != 'o' || name.empty() || !names.insert(name).second) {
            e.policy_inventory_inspection_status = "invalid_list";
            return;
        }
        for (const auto& field : {"description", "mimeType", "template"}) {
            auto value = object.get(field);
            if (value && value->kind != 's') { e.policy_inventory_inspection_status = "invalid_list"; return; }
        }
        auto schema = object.get("inputSchema");
        auto args = object.get("arguments");
        if ((type == "tool" && (!schema || schema->kind != 'o')) ||
            (type == "prompt" && args && args->kind != 'a')) {
            e.policy_inventory_inspection_status = "invalid_list"; return;
        }
    }
    for (const auto& item : objects->children) {
        const Json& object = item.second;
        const std::string name = object.string(type == "resource" ? "uri" : "name");
        bool known = false;
        auto compare = [&](const std::string& field, const std::string& expected) {
            if (object.string(field) != expected) changed(type, name, field);
        };
        if (type == "tool" && tools.count(name)) {
            const auto& t = *tools.at(name);
            known = true;
            if (t.hasDescription) compare("description", t.description);
            if (t.hasInputSchema && canonicalJson(*object.get("inputSchema")) != t.inputSchemaKey)
                changed(type, name, "inputSchema");
        }
        if (type == "resource" && resources.count(name)) {
            const auto& r = *resources.at(name);
            known = true;
            if (r.hasName) compare("name", r.name);
            if (r.hasDescription) compare("description", r.description);
            if (r.hasMimeType) compare("mimeType", r.mimeType);
        }
        if (type == "prompt" && prompts.count(name)) {
            const auto& p = *prompts.at(name);
            known = true;
            if (p.hasDescription) compare("description", p.description);
            auto args = object.get("arguments");
            Json empty_args; empty_args.kind = 'a';
            if (p.hasArguments && canonicalJson(args ? *args : empty_args) != p.argumentsKey) changed(type, name, "arguments");
            if (object.get("template") && p.hasTemplate) compare("template", p.template_str);
        }
        if (!known) add(type == "tool" ? SIG_MCP_UNKNOWN_TOOL : type == "resource" ?
            SIG_MCP_UNKNOWN_RESOURCE : SIG_MCP_UNKNOWN_PROMPT, "unknown_" + type, type, name, "");
    }
    auto params = request.get("params");
    const bool complete_list = request_id && !result->get("nextCursor") && (!params || !params->get("cursor"));
    if (!complete_list) {
        if (e.policy_inventory_inspection_status != "drift_limit") e.policy_inventory_inspection_status = "partial_list";
        return;
    }
    auto removed = [&](const std::string& name, const std::string& path) {
        // Wildcard entries may describe multiple servers: absence is only
        // meaningful for a baseline explicitly scoped to this endpoint.
        if (!path.empty() && scope(path) && !names.count(name))
            add(SIG_MCP_INVENTORY_CHANGE, "object_removed", type, name, "");
    };
    if (type == "tool") for (const auto& t : inventory.mcp_tools) removed(t.name, t.endpointPath);
    if (type == "resource") for (const auto& r : inventory.mcp_resources) removed(r.uri, r.endpointPath);
    if (type == "prompt") for (const auto& p : inventory.mcp_prompts) removed(p.name, p.endpointPath);
}
