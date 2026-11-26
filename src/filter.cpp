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

#include "http_io.h"
#include "tls_client.h"
// filter.cpp
#include "filter.h"
#include "bounded_json.h"
#include "cobject.h"
#include "inventory_decode.h"

#include <algorithm>
#include <set>
#include <limits>
#include <cctype>
#include <sstream>
#include <unistd.h>
#include <mutex>

// boost json
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

// boost http
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

static std::shared_ptr<const PolicyInventory> policy_inventory_snapshot;

using tcp = boost::asio::ip::tcp;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;

// ==============================
// GLOBAL INVENTORY
// ==============================
PolicyInventory policy_inventory;
std::mutex policy_inventory_mutex;
std::atomic<uint64_t> policy_inventory_version{0};

// Latches to true the first time ctrl delivers a "patterns" array (possibly
// empty). Never reset: once the pattern set is managed, the probe must not
// fall back to the built-in mcp_heavy_tool_usage pattern.
static std::atomic<bool> mcp_patterns_managed{false};





// ==============================
// HTTP CLIENT
// ==============================
bool Filter::sendHttpRequest(
    bool is_https,
    const std::string& host,
    const std::string& port,
    const std::string& target,
    const std::string& method,
    const std::string& body,
    const std::string& auth,
    const std::vector<std::string>& headers,
    const std::string& content_type,
    std::string* response
) {
    try {
        std::map<std::string, std::string> parsedHeaders;
        for (const auto& header : headers) {
            const auto colon = header.find(':');
            if (colon == std::string::npos) continue;
            std::string value = header.substr(colon + 1);
            const auto first = value.find_first_not_of(" ");
            value = first == std::string::npos ? "" : value.substr(first);
            const auto last = value.find_last_not_of(" ");
            if (last != std::string::npos) value.resize(last + 1);
            parsedHeaders[header.substr(0, colon)] = value;
        }
        // One deadline covers DNS, connection, TLS, write and read. Close()
        // interrupts the exchange even if the remote peer never responds.
        const auto result = bounded_http::request(is_https, host, port, target,
            method, body, auth, parsedHeaders, body.empty() ? "" : content_type,
            std::chrono::seconds(60), [&] { return !source_status.load(); },
            4 * 1024 * 1024, af_tls_verify, af_tls_ca_file);
        if (result.result() != http::status::ok) {
            SysLog((char*)("[Filter] Inventory HTTP error: " + std::to_string(result.result_int())).c_str());
            return false;
        }
        if (response) *response = result.body();
        return true;
    } catch (const std::exception& error) {
        SysLog((char*)error.what());
        return false;
    }
}

// ==============================
// FETCH INVENTORY (NEW)
// ==============================
bool Filter::fetchInventory() {

    try {
        bool is_https = (af_url.find("https://") == 0);
        bool is_http = (af_url.find("http://") == 0);
        if (!is_https && !is_http) {
            SysLog((char*)"[Filter] Alertflex URL must start with http:// or https://");
            return false;
        }

        std::string url = af_url.substr(is_https ? 8 : 7);

        // -------- HOST + BASE PATH --------
        size_t slash = url.find('/');
        std::string host_part = (slash != std::string::npos) ? url.substr(0, slash) : url;
        std::string base_path = (slash != std::string::npos) ? url.substr(slash) : "";

        // -------- NORMALIZE PATH --------
        if (!base_path.empty() && base_path.back() == '/') {
            base_path.pop_back();
        }

        // -------- FINAL TARGET (NEW INVENTORY ENDPOINT) --------
        std::string target = base_path + "/inventory/" + asset_name;

        // -------- HOST / PORT --------
        std::string host, port_str;

        size_t colon = host_part.find(':');
        if (colon != std::string::npos) {
            host = host_part.substr(0, colon);
            port_str = host_part.substr(colon + 1);
        } else {
            host = host_part;
            port_str = is_https ? "443" : "80";
        }

        std::string auth = "Bearer " + af_key;
        std::string response;

        if (!sendHttpRequest(
                is_https,
                host,
                port_str,
                target,
                "GET",
                "",
                auth,
                {"Accept: application/json"},
                "application/json",
                &response)) {

            SysLog((char*)"[Filter] Inventory HTTP failed");
            return false;
        }

        // Build a candidate snapshot locally. Readers retain the last valid
        // snapshot if validation fails; partially parsed policy must not leak.
        // -------- PARSE JSON --------
        PolicyInventory new_inventory;
        bool has_patterns = false;
        decodeInventory(response, asset_name, project_id, false, new_inventory, has_patterns);
        size_t endpoint_count = new_inventory.endpoints.size();
        size_t agent_count = new_inventory.agents.size();
        size_t tool_count = new_inventory.mcp_tools.size();
        size_t resource_count = new_inventory.mcp_resources.size();
        size_t prompt_count = new_inventory.mcp_prompts.size();
        size_t pattern_count = new_inventory.patterns.size();
        uint64_t next_version;

        {
            std::lock_guard<std::mutex> lock(policy_inventory_mutex);
            next_version = policy_inventory_version.load() + 1;
            new_inventory.version = next_version;
            new_inventory.fetchedAt = std::chrono::steady_clock::now();

            // Update global inventory
            auto next_snapshot = std::make_shared<const PolicyInventory>(new_inventory);
            policy_inventory = std::move(new_inventory);
            policy_inventory_snapshot = std::move(next_snapshot);
            if (has_patterns) mcp_patterns_managed.store(true);
            policy_inventory_version.store(next_version);

        }
        
        if (log_debug) {
            SysLog((char*)"Next resources have been fetched:");
    
            // Create a JSON string with the full inventory
            boost::property_tree::ptree root;
    
            // Adding a version
            root.put("version", policy_inventory.version);
    
            // Adding endpoints
            boost::property_tree::ptree endpoints_array;
            for (const auto& ep : policy_inventory.endpoints) {
                boost::property_tree::ptree ep_node;
                ep_node.put("path", ep.path);
                ep_node.put("method", ep.method);
                ep_node.put("type", ep.type);
                ep_node.put("pipeline", ep.pipeline);
                ep_node.put("logBody", ep.logbody);
                ep_node.put("status", ep.status);
                ep_node.put("apiCalls", ep.apicalls);
                endpoints_array.push_back(std::make_pair("", ep_node));
            }
            root.add_child("endpoints", endpoints_array);
    
            // Add mcp_tools
            boost::property_tree::ptree tools_array;
            for (const auto& tool : policy_inventory.mcp_tools) {
                boost::property_tree::ptree tool_node;
                tool_node.put("name", tool.name);
                tool_node.put("description", tool.description);
                tool_node.put("endpointPath", tool.endpointPath);
                tool_node.put("createdAt", tool.createdAt);
                tool_node.put("lastChanged", tool.lastChanged);
                // inputSchema is already a JSON string, but for correct output we add it as is
                try {
                    std::stringstream schema_ss(tool.inputSchema);
                    boost::property_tree::ptree schema_node;
                    boost::property_tree::read_json(schema_ss, schema_node);
                    tool_node.add_child("inputSchema", schema_node);
                } catch (...) {
                    tool_node.put("inputSchema", tool.inputSchema);
                }
                tools_array.push_back(std::make_pair("", tool_node));
            }
            root.add_child("mcp_tools", tools_array);
    
            // Add mcp_resources
            boost::property_tree::ptree resources_array;
            for (const auto& resource : policy_inventory.mcp_resources) {
                boost::property_tree::ptree resource_node;
                resource_node.put("uri", resource.uri);
                resource_node.put("name", resource.name);
                resource_node.put("description", resource.description);
                resource_node.put("mimeType", resource.mimeType);
                resource_node.put("endpointPath", resource.endpointPath);
                resource_node.put("createdAt", resource.createdAt);
                resource_node.put("lastChanged", resource.lastChanged);
                resources_array.push_back(std::make_pair("", resource_node));
            }
            root.add_child("mcp_resources", resources_array);
    
            // Add mcp_prompts
            boost::property_tree::ptree prompts_array;
            for (const auto& prompt : policy_inventory.mcp_prompts) {
                boost::property_tree::ptree prompt_node;
                prompt_node.put("name", prompt.name);
                prompt_node.put("description", prompt.description);
                prompt_node.put("template", prompt.template_str);
                prompt_node.put("endpointPath", prompt.endpointPath);
                prompt_node.put("createdAt", prompt.createdAt);
                prompt_node.put("lastChanged", prompt.lastChanged);
                prompts_array.push_back(std::make_pair("", prompt_node));
            }
            root.add_child("mcp_prompts", prompts_array);

            // Add trace patterns
            boost::property_tree::ptree patterns_array;
            for (const auto& pat : policy_inventory.patterns) {
                boost::property_tree::ptree pat_node;
                pat_node.put("id", pat.id);
                pat_node.put("track", pat.track);
                pat_node.put("window_sec", pat.window_sec);
                pat_node.put("min_events", pat.min_events);
                pat_node.put("cooldown_sec", pat.cooldown_sec);
                pat_node.put("pattern_severity", pat.pattern_severity);
                pat_node.put("order_strict", pat.order_strict);
                pat_node.put("source", pat.source);

                boost::property_tree::ptree conds_array;
                for (const auto& cond : pat.conditions) {
                    boost::property_tree::ptree cond_node;
                    cond_node.put("track", cond.track);
                    cond_node.put("url_contains", cond.url_contains);
                    cond_node.put("http_method", cond.http_method);
                    cond_node.put("mcp_method", cond.mcp_method);
                    cond_node.put("body_contains", cond.body_contains);
                    cond_node.put("status_eq", cond.status_eq);
                    cond_node.put("case_sensitive", cond.case_sensitive);
                    conds_array.push_back(std::make_pair("", cond_node));
                }
                pat_node.add_child("conditions", conds_array);
                patterns_array.push_back(std::make_pair("", pat_node));
            }
            root.add_child("patterns", patterns_array);

            // Convert to JSON string with formatting
            std::stringstream json_ss;
            boost::property_tree::write_json(json_ss, root, true); // true = pretty print
            std::string json_str = json_ss.str();
    
            SysLog((char*)json_str.c_str());
        }

        SysLog((char*)("[Filter] Inventory updated: endpoints=" +
            std::to_string(endpoint_count) +
            ", agents=" + std::to_string(agent_count) +
            ", mcp_tools=" + std::to_string(tool_count) +
            ", mcp_resources=" + std::to_string(resource_count) +
            ", mcp_prompts=" + std::to_string(prompt_count) +
            ", patterns=" + std::to_string(pattern_count)).c_str());

        return true;

    } catch (std::exception const& e) {
        SysLog((char*)e.what());
        return false;
    }
}

// ==============================
// GETTER FUNCTIONS
// ==============================
std::shared_ptr<const PolicyInventory> Filter::getInventorySnapshot() {
    std::lock_guard<std::mutex> lock(policy_inventory_mutex);
    return policy_inventory_snapshot;
}

PolicyInventory Filter::getInventory() {
    std::lock_guard<std::mutex> lock(policy_inventory_mutex);
    return policy_inventory;
}

std::vector<Endpoint> Filter::getEndpoints() {
    std::lock_guard<std::mutex> lock(policy_inventory_mutex);
    return policy_inventory.endpoints;
}

std::vector<TracePattern> Filter::getPatterns() {
    std::lock_guard<std::mutex> lock(policy_inventory_mutex);
    return policy_inventory.patterns;
}

uint64_t Filter::getInventoryVersion() {
    return policy_inventory_version.load();
}

bool Filter::patternsManaged() {
    return mcp_patterns_managed.load();
}

// ==============================
// MAIN LOOP
// ==============================
bool Filter::Go() {
    
    fetchInventory();  // Now fetches full inventory

    // Interactive access/key changes need prompt propagation; passive
    // collection keeps the existing, lower-frequency inventory polling.
    WaitForStop(std::chrono::seconds(60));

    return source_status;
}
