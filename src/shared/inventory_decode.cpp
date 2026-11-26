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

#include "inventory_decode.h"
#include "bounded_json.h"
#include <algorithm>
#include <cctype>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <charconv>
#include <boost/property_tree/json_parser.hpp>

static std::string lowerCopy(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return out;
}
static void normalizeTracePattern(TracePattern& pat) {
    if (pat.track.empty())
        pat.track = "*";
    if (pat.window_sec <= 0)
        pat.window_sec = 300;
    if (pat.min_events < 1)
        pat.min_events = 1;
    if (pat.cooldown_sec < 0)
        pat.cooldown_sec = 0;
    if (pat.pattern_severity < 1)
        pat.pattern_severity = 1;
}
void decodeInventory(const std::string& response, const std::string& asset_name,
    const std::string& project_id, bool include_credentials,
    PolicyInventory& new_inventory, bool& has_patterns) {
    has_patterns = false;
        Json typed_inventory;
        if (!parseBoundedJson(response, typed_inventory, 4194304, 65536) || typed_inventory.kind != 'o')
            throw std::runtime_error("invalid or oversized inventory JSON");
        auto validate_objects = [&](const std::string& key, const std::string& identity,
                                    const std::vector<std::string>& fields) {
            auto objects = typed_inventory.get(key);
            if (!objects) return;
            if (objects->kind != 'a') throw std::runtime_error(key + " must be an array");
            for (const auto& entry : objects->children) {
                if (entry.second.kind != 'o' || entry.second.string(identity).empty())
                    throw std::runtime_error("invalid " + key + " identity");
                for (const auto& field : fields) {
                    auto value = entry.second.get(field);
                    if (value && value->kind != 's')
                        throw std::runtime_error("invalid " + key + " " + field);
                }
            }
        };
        validate_objects("mcp_tools", "name", {"name", "description", "endpointPath"});
        validate_objects("mcp_resources", "uri", {"uri", "name", "description", "mimeType", "endpointPath"});
        validate_objects("mcp_prompts", "name", {"name", "description", "template", "endpointPath"});
        std::stringstream ss(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ss, pt);
        new_inventory = PolicyInventory{};
        auto discovery_targets = pt.get_child_optional("discoveryTargets");
        if (discovery_targets) for (const auto& node : *discovery_targets) {
            DiscoveryTarget target;
            target.type = node.second.get<string>("type", "");
            target.path = node.second.get<string>("path", "");
            target.method = node.second.get<string>("method", "");
            target.state = node.second.get<string>("state", "unconfirmed");
            target.alerted = node.second.get<bool>("alertCreated", false);
            target.route_template = node.second.get<string>("routeTemplate", "");
            new_inventory.discovery_targets.push_back(std::move(target));
        }
        if (typed_inventory.string("asset") != asset_name ||
                (!project_id.empty() && typed_inventory.string("projectId") != project_id))
            throw std::runtime_error("inventory scope mismatch");
        auto target_version = typed_inventory.get("policyTargetVersion");
        if (!target_version || target_version->kind != 'd' ||
                (target_version->text != "1" && target_version->text != "2" &&
                 target_version->text != "3" && target_version->text != "4"))
            throw std::runtime_error("inventory target decisions unavailable");
        auto auth_version = typed_inventory.get("agentAuthVersion");
        auto require_key = typed_inventory.get("requireAgentKey");
        if (auth_version) {
            if (auth_version->kind != 'd' || auth_version->text != "1" || !require_key || require_key->kind != 'b')
                throw std::runtime_error("invalid agent authentication contract");
            new_inventory.agentAuthPresent = true;
            new_inventory.requireAgentKey = require_key->text == "true";
        } else if (target_version->text != "1" || require_key)
            throw std::runtime_error("agent authentication contract unavailable");
        if (auto require_group = typed_inventory.get("requireAgentGroup")) {
            if (require_group->kind != 'b') throw std::runtime_error("invalid group policy requirement");
            new_inventory.requireAgentGroup = require_group->text == "true";
        }
        const bool daily_usage = target_version->text == "4";
        if (!daily_usage && new_inventory.requireAgentGroup != (target_version->text == "3"))
            throw std::runtime_error("group policy requirement and inventory version disagree");
        auto usage_end = typed_inventory.get("tokenUsageValidUntil");
        if (daily_usage) {
            if (!usage_end || usage_end->kind != 'd') throw std::runtime_error("missing daily usage cutoff");
            const char* end = usage_end->text.data() + usage_end->text.size();
            int64_t cutoff = 0;
            auto parsed = std::from_chars(usage_end->text.data(), end, cutoff);
            if (parsed.ec != std::errc{} || parsed.ptr != end || cutoff <= 0 || cutoff % 86400000 != 0)
                throw std::runtime_error("invalid daily usage cutoff");
            new_inventory.tokenUsageValidUntil = cutoff;
        } else if (usage_end) {
            throw std::runtime_error("daily usage cutoff requires inventory version 4");
        }
        if (auto revision = typed_inventory.get("accessPolicyRevision")) {
            if (revision->kind != 's' || revision->text.size() != 64 ||
                    revision->text.find_first_not_of("0123456789abcdef") != std::string::npos)
                throw std::runtime_error("invalid access policy revision");
            new_inventory.accessPolicyRevision = revision->text;
        }
        auto block_state = [](const Json& object) {
            auto value = object.get("blockStatus");
            if (!value || value->kind != 's' || (value->text != "active" && value->text != "blocked"))
                throw std::runtime_error("invalid target blockStatus");
            return value->text;
        };
        new_inventory.targetDecisionsPresent = true;

        // ===== PARSE CLIENT AGENT DECISIONS =====
        // Parse from the typed tree so strings/bools cannot be silently coerced into statuses.
        auto typed_agents = typed_inventory.get("agents");
        if (typed_agents) {
            if (typed_agents->kind != 'a') throw std::runtime_error("agents must be an array");
            new_inventory.agentsPresent = true;
            std::set<std::string> ids;
            std::set<std::string> bindings;
            std::set<std::string> credential_ids;
            auto text = [](const Json& object, const std::string& field, size_t max) {
                auto value = object.get(field);
                if (!value) return std::string();
                if (value->kind != 's' || value->text.size() > max)
                    throw std::runtime_error("invalid agent " + field);
                return value->text;
            };
            auto number = [](const Json& object, const std::string& field) -> uint64_t {
                auto value = object.get(field);
                if (!value || value->kind == 'n') return 0;
                if (value->kind != 'd' || value->text.empty() ||
                    value->text.find_first_not_of("0123456789") != std::string::npos)
                    throw std::runtime_error("invalid agent " + field);
                uint64_t result = 0;
                for (char digit : value->text) {
                    unsigned d = static_cast<unsigned>(digit - '0');
                    if (result > (std::numeric_limits<uint64_t>::max() - d) / 10)
                        throw std::runtime_error("agent numeric field overflow");
                    result = result * 10 + d;
                }
                return result;
            };
            for (const auto& entry : typed_agents->children) {
                const Json& object = entry.second;
                if (object.kind != 'o') throw std::runtime_error("invalid agent object");
                InventoryAgent agent;
                agent.id = text(object, "id", 20);
                if (agent.id.empty() || agent.id.front() == '0' || agent.id.find_first_not_of("0123456789") != std::string::npos ||
                    !ids.insert(agent.id).second)
                    throw std::runtime_error("invalid or duplicate agent ID");
                if (object.get("consumerId") && text(object, "consumerId", 20) != agent.id)
                    throw std::runtime_error("consumerId differs from agent ID");
                agent.name = text(object, "name", 1020);
                agent.ip = text(object, "ip", 512);
                agent.version = text(object, "version", 1020);
                agent.jsonRpc = text(object, "jsonRpc", 1020);
                agent.assetName = text(object, "assetName", 512);
                agent.apiCalls = number(object, "apiCalls");
                agent.blockStatus = text(object, "blockStatus", 16);
                if (agent.blockStatus != "active" && agent.blockStatus != "blocked")
                    throw std::runtime_error("invalid agent blockStatus");
                agent.blockIncidentId = text(object, "blockIncidentId", 36);
                agent.blockReason = text(object, "blockReason", 4096);
                agent.blockedAt = number(object, "blockedAt");
                auto auto_block = object.get("autoBlockEnabled");
                if (auto_block && auto_block->kind != 'b') throw std::runtime_error("invalid autoBlockEnabled");
                agent.autoBlockEnabled = auto_block && auto_block->text == "true";
                // Asset-only binding: a legacy bindingAssetName is accepted as
                // an alias, but probe is never part of agent identity.
                agent.bindingAssetName = text(object, "bindingAssetName", 512);
                agent.correlationUid = text(object, "correlationUid", 4096);
                // Discovery without authenticated identity is valid, but cannot authorize.
                if (agent.bindingAssetName.empty() && !agent.correlationUid.empty())
                    agent.bindingAssetName = agent.assetName;
                if (include_credentials) {
                auto expires = object.get("keyExpiresAt");
                if (expires && expires->kind != 'n') {
                    int64_t timestamp = 0;
                    if (expires->kind != 'd') throw std::runtime_error("invalid key expiry");
                    auto parsed = std::from_chars(expires->text.data(), expires->text.data() + expires->text.size(), timestamp);
                    if (parsed.ec != std::errc{} || parsed.ptr != expires->text.data() + expires->text.size())
                        throw std::runtime_error("invalid key expiry");
                    agent.keyExpiresAt = timestamp;
                }
                agent.keyId = text(object, "keyId", 32);
                agent.keyHash = text(object, "keyHash", 64);
                agent.keyStatus = text(object, "keyStatus", 16);
                if (!agent.keyId.empty() || !agent.keyHash.empty() || !agent.keyStatus.empty()) {
                    auto hex = [](const std::string& s, size_t size) {
                        return s.size() == size && s.find_first_not_of("0123456789abcdef") == std::string::npos;
                    };
                    if (!new_inventory.agentAuthPresent || target_version->text == "1" ||
                            !hex(agent.keyId, 32) || !hex(agent.keyHash, 64) ||
                            (agent.keyStatus != "active" && agent.keyStatus != "revoked") ||
                            !credential_ids.insert(agent.keyId).second || agent.bindingAssetName.empty() ||
                            agent.correlationUid.rfind("auth:", 0) != 0)
                        throw std::runtime_error("invalid agent credential");
                }
                }
                agent.createdAt = number(object, "createdAt");
                agent.lastObserved = number(object, "lastObserved");
                agent.consumerGroupId = text(object, "consumerGroupId", 20);
                if (!agent.consumerGroupId.empty() &&
                    (agent.consumerGroupId.front() == '0' || agent.assetName != asset_name ||
                     agent.consumerGroupId.find_first_not_of("0123456789") != std::string::npos))
                    throw std::runtime_error("invalid agent consumerGroupId");
                if (auto risk = object.get("riskScore")) {
                    if (risk->kind != 'd' || risk->text.find_first_not_of("0123456789") != std::string::npos)
                        throw std::runtime_error("invalid agent riskScore");
                    agent.riskScore = std::stoi(risk->text);
                    if (agent.riskScore > 100) throw std::runtime_error("agent riskScore out of range");
                }
                if (auto used = object.get("tokensUsedToday"); used && used->kind != 'n')
                    agent.tokensUsedToday = number(object, "tokensUsedToday");
                const bool any_binding = !agent.bindingAssetName.empty() || !agent.correlationUid.empty();
                if (any_binding) {
                    if (agent.bindingAssetName.empty() || agent.correlationUid.empty())
                        throw std::runtime_error("incomplete agent binding");
                    auto part = [](const std::string& value) { return std::to_string(value.size()) + ":" + value; };
                    const std::string key = part(agent.bindingAssetName) + part(agent.correlationUid);
                    if (!bindings.insert(key).second) throw std::runtime_error("ambiguous agent binding");
                }
                if (agent.assetName != asset_name && agent.bindingAssetName != asset_name)
                    throw std::runtime_error("agent asset scope mismatch");
                new_inventory.agents.push_back(std::move(agent));
            }
        }

        // ===== PARSE CONSUMER GROUPS =====
        if (auto groups = typed_inventory.get("consumerGroups")) {
            if (groups->kind != 'a') throw std::runtime_error("consumerGroups must be an array");
            std::set<std::string> group_ids;
            for (const auto& entry : groups->children) {
                const Json& object = entry.second;
                if (object.kind != 'o') throw std::runtime_error("invalid consumer group");
                ConsumerGroup group;
                auto field = [&](const char* name, size_t max) {
                    auto value = object.get(name);
                    if (!value) return std::string();
                    if (value->kind != 's' || value->text.size() > max)
                        throw std::runtime_error(std::string("invalid consumer group ") + name);
                    return value->text;
                };
                group.id = field("id", 20);
                if (group.id.empty() || group.id.front() == '0' || group.id.find_first_not_of("0123456789") != std::string::npos ||
                    !group_ids.insert(group.id).second)
                    throw std::runtime_error("invalid consumer group id");
                if (object.get("assetName") && field("assetName", 512) != asset_name)
                    throw std::runtime_error("consumer group asset scope mismatch");
                group.name = field("name", 128);
                if (auto enabled = object.get("enabled")) {
                    if (enabled->kind != 'b') throw std::runtime_error("invalid consumer group enabled");
                    group.enabled = enabled->text == "true";
                }
                group.policyMode = field("policyMode", 16);
                if (group.policyMode != "allow_all" && group.policyMode != "allow_confirmed" &&
                    group.policyMode != "allow_list")
                    throw std::runtime_error("invalid consumer group policyMode");
                auto max_tokens = object.get("maxTokensPerDay");
                if (max_tokens) {
                    if (max_tokens->kind != 'd' || max_tokens->text.find_first_not_of("0123456789") != std::string::npos)
                        throw std::runtime_error("invalid consumer group maxTokensPerDay");
                    group.maxTokensPerDay = std::stoull(max_tokens->text);
                }
                if (auto threshold = object.get("riskScoreThreshold")) {
                    if (threshold->kind != 'd' || threshold->text.find_first_not_of("0123456789") != std::string::npos)
                        throw std::runtime_error("invalid consumer group riskScoreThreshold");
                    group.riskScoreThreshold = std::stoi(threshold->text);
                    if (group.riskScoreThreshold > 100) throw std::runtime_error("riskScoreThreshold out of range");
                }
                if (auto version = object.get("version")) {
                    if (version->kind != 'd' || version->text.find_first_not_of("0123456789") != std::string::npos)
                        throw std::runtime_error("invalid consumer group version");
                    group.version = std::stoull(version->text);
                }
                if (auto rules = object.get("endpoints")) {
                    if (rules->kind != 'a') throw std::runtime_error("invalid consumer group endpoints");
                    for (const auto& rule_entry : rules->children) {
                        const Json& rule = rule_entry.second;
                        if (rule.kind != 'o') throw std::runtime_error("invalid consumer group endpoint");
                        ConsumerGroupEndpoint endpoint;
                        auto rule_text = [&](const char* name, size_t max) {
                            auto value = rule.get(name);
                            if (!value) return std::string();
                            if (value->kind != 's' || value->text.size() > max)
                                throw std::runtime_error(std::string("invalid group endpoint ") + name);
                            return value->text;
                        };
                        endpoint.protocol = rule_text("protocol", 8);
                        endpoint.method = rule_text("method", 128);
                        endpoint.path = rule_text("path", 1024);
                        endpoint.tool = rule_text("tool", 255);
                        endpoint.action = rule_text("action", 8);
                        if (endpoint.action != "allow" && endpoint.action != "deny")
                            throw std::runtime_error("invalid group endpoint action");
                        if (auto priority = rule.get("priority")) {
                            if (priority->kind != 'd')
                                throw std::runtime_error("invalid group endpoint priority");
                            const auto* end = priority->text.data() + priority->text.size();
                            auto parsed = std::from_chars(priority->text.data(), end, endpoint.priority);
                            if (parsed.ec != std::errc{} || parsed.ptr != end)
                                throw std::runtime_error("invalid group endpoint priority");
                        }
                        group.endpoints.push_back(std::move(endpoint));
                    }
                }
                std::stable_sort(group.endpoints.begin(), group.endpoints.end(), [](const auto& left, const auto& right) {
                    return left.priority < right.priority;
                });
                new_inventory.consumer_groups.push_back(std::move(group));
            }
        }

        // ===== PARSE ENDPOINTS =====
        auto endpoints_node = pt.get_child_optional("endpoints");
        auto endpoints_contract = typed_inventory.get("endpoints");
        if (!endpoints_contract || endpoints_contract->kind != 'a') throw std::runtime_error("invalid endpoints");
        if (endpoints_node) {
            for (const auto& item : endpoints_node.get()) {
                const auto& ep_json = item.second;
                Endpoint ep;
                ep.path = ep_json.get<std::string>("path", "");
                ep.method = ep_json.get<std::string>("method", "");
                ep.type = ep_json.get<std::string>("type", "");
                ep.piiMode = ep_json.get<std::string>("piiMode", "none");
                ep.attachmentsAllowed = ep_json.get<bool>("attachmentsAllowed", true);
                ep.pipeline = ep_json.get<std::string>("pipeline", "indef");
                ep.logbody = ep_json.get<int>("logBody", 0);
                ep.status = ep_json.get<std::string>("status", "");
                ep.apicalls = ep_json.get<int>("apiCalls", 0);
                auto typed_endpoints = typed_inventory.get("endpoints");
                if (!typed_endpoints || typed_endpoints->kind != 'a' || new_inventory.endpoints.size() >= typed_endpoints->children.size())
                    throw std::runtime_error("invalid endpoints");
                const auto& typed_endpoint = typed_endpoints->children[new_inventory.endpoints.size()].second;
                if (typed_endpoint.kind != 'o') throw std::runtime_error("invalid endpoint object");
                auto pii = typed_endpoint.get("piiMode"), attachments = typed_endpoint.get("attachmentsAllowed");
                if (pii && (pii->kind != 's' || (pii->text != "none" && pii->text != "block" && pii->text != "redact")))
                    throw std::runtime_error("invalid endpoint piiMode");
                if (attachments && attachments->kind != 'b') throw std::runtime_error("invalid endpoint attachmentsAllowed");
                for (const auto& field : {"path", "method", "type"}) {
                    auto value = typed_endpoint.get(field);
                    if (!value || value->kind != 's' || value->text.empty() || value->text.size() > 1024)
                        throw std::runtime_error("invalid endpoint key");
                }
                auto ready = typed_endpoint.get("authorizationReady");
                if (ready && ready->kind != 'b') throw std::runtime_error("invalid endpoint authorization state");
                ep.authorizationReady = ready && ready->text == "true";
                auto approved = typed_endpoint.get("accessApproved");
                if (approved && approved->kind != 'b') throw std::runtime_error("invalid endpoint access approval");
                ep.accessApproved = approved && approved->text == "true";
                ep.blockStatus = block_state(typed_endpoint);
                new_inventory.endpoints.push_back(ep);
            }
        }

        // ===== PARSE MCP TOOLS =====
        auto mcp_tools_node = pt.get_child_optional("mcp_tools");
        if (mcp_tools_node) {
            for (const auto& item : mcp_tools_node.get()) {
                const auto& tool_json = item.second;
                McpTool tool;
                tool.name = tool_json.get<std::string>("name", "");
                tool.description = tool_json.get<std::string>("description", "");
                tool.endpointPath = tool_json.get<std::string>("endpointPath", "");
                tool.createdAt = tool_json.get<std::string>("createdAt", "");
                tool.lastChanged = tool_json.get<std::string>("lastChanged", "");
                auto typed_tools = typed_inventory.get("mcp_tools");
                if (typed_tools && typed_tools->kind == 'a' &&
                    new_inventory.mcp_tools.size() < typed_tools->children.size()) {
                    const auto& typed_tool = typed_tools->children[new_inventory.mcp_tools.size()].second;
                    tool.hasDescription = typed_tool.get("description") != nullptr;
                    auto schema = typed_tool.get("inputSchema");
                    if (schema) {
                        Json decoded;
                        if (schema->kind == 's') {
                            if (!parseBoundedJson(schema->text, decoded) || decoded.kind != 'o')
                                throw std::runtime_error("invalid tool inputSchema");
                            tool.inputSchemaKey = canonicalJson(decoded);
                        } else {
                            if (schema->kind != 'o') throw std::runtime_error("inputSchema must be an object");
                            tool.inputSchemaKey = canonicalJson(*schema);
                        }
                        tool.hasInputSchema = true;
                    }
                }
                
                // Parse inputSchema as string
                auto schema_node = tool_json.get_child_optional("inputSchema");
                if (schema_node) {
                    if (schema_node->empty() && !schema_node->data().empty()) {
                        tool.inputSchema = schema_node->data();
                    } else {
                        std::stringstream schema_ss;
                        boost::property_tree::write_json(schema_ss, schema_node.get());
                        tool.inputSchema = schema_ss.str();
                    }
                } else {
                    tool.inputSchema = "{}";
                }
                
                new_inventory.mcp_tools.push_back(tool);
            }
        }

        // ===== PARSE MCP RESOURCES =====
        auto mcp_resources_node = pt.get_child_optional("mcp_resources");
        if (mcp_resources_node) {
            for (const auto& item : mcp_resources_node.get()) {
                const auto& resource_json = item.second;
                McpResource resource;
                resource.uri = resource_json.get<std::string>("uri", "");
                resource.name = resource_json.get<std::string>("name", "");
                resource.description = resource_json.get<std::string>("description", "");
                resource.mimeType = resource_json.get<std::string>("mimeType", "");
                resource.endpointPath = resource_json.get<std::string>("endpointPath", "");
                resource.createdAt = resource_json.get<std::string>("createdAt", "");
                resource.lastChanged = resource_json.get<std::string>("lastChanged", "");
                auto typed_resources = typed_inventory.get("mcp_resources");
                if (typed_resources && typed_resources->kind == 'a' &&
                    new_inventory.mcp_resources.size() < typed_resources->children.size()) {
                    const auto& typed_resource = typed_resources->children[new_inventory.mcp_resources.size()].second;
                    resource.hasName = typed_resource.get("name") != nullptr;
                    resource.hasDescription = typed_resource.get("description") != nullptr;
                    resource.hasMimeType = typed_resource.get("mimeType") != nullptr;
                }
                new_inventory.mcp_resources.push_back(resource);
            }
        }

        // ===== PARSE MCP PROMPTS =====
        auto mcp_prompts_node = pt.get_child_optional("mcp_prompts");
        if (mcp_prompts_node) {
            for (const auto& item : mcp_prompts_node.get()) {
                const auto& prompt_json = item.second;
                McpPrompt prompt;
                prompt.name = prompt_json.get<std::string>("name", "");
                prompt.description = prompt_json.get<std::string>("description", "");
                prompt.template_str = prompt_json.get<std::string>("template", "");
                prompt.endpointPath = prompt_json.get<std::string>("endpointPath", "");
                prompt.createdAt = prompt_json.get<std::string>("createdAt", "");
                prompt.lastChanged = prompt_json.get<std::string>("lastChanged", "");
                auto typed_prompts = typed_inventory.get("mcp_prompts");
                if (typed_prompts && typed_prompts->kind == 'a' &&
                    new_inventory.mcp_prompts.size() < typed_prompts->children.size()) {
                    const auto& typed_prompt = typed_prompts->children[new_inventory.mcp_prompts.size()].second;
                    prompt.hasDescription = typed_prompt.get("description") != nullptr;
                    prompt.hasTemplate = typed_prompt.get("template") != nullptr;
                    auto arguments = typed_prompt.get("arguments");
                    if (arguments) {
                        if (arguments->kind != 'a') throw std::runtime_error("prompt arguments must be an array");
                        prompt.argumentsKey = canonicalJson(*arguments);
                        prompt.hasArguments = true;
                    }
                }
                new_inventory.mcp_prompts.push_back(prompt);
            }
        }

        // ===== PARSE TRACE PATTERNS =====
        // Alertflex publishes canonical TracePattern objects only:
        //   {"id","name","track","window_sec","min_events",
        //    "cooldown_sec","pattern_severity","order_strict","conditions"}.
        // The old single-string trigger payload is not parsed.
        auto cfg_int = [](const boost::property_tree::ptree& n,
                          const std::string& key, int def) -> int {
            auto v = n.get_optional<int>(key);
            return v ? *v : def;
        };
        auto cfg_str = [](const boost::property_tree::ptree& n,
                          const std::string& key,
                          const std::string& def) -> std::string {
            auto v = n.get_optional<std::string>(key);
            return v ? *v : def;
        };
        auto cfg_bool = [](const boost::property_tree::ptree& n,
                           const std::string& key, bool def) -> bool {
            auto v = n.get_optional<bool>(key);
            return v ? *v : def;
        };

        auto parse_condition = [&](const boost::property_tree::ptree& node) -> TraceCondition {
            TraceCondition cond;
            cond.track = cfg_str(node, "track", "");
            cond.url_contains = cfg_str(node, "url_contains", "");
            cond.http_method = cfg_str(node, "http_method", "");
            cond.mcp_method = cfg_str(node, "mcp_method", "");
            cond.body_contains = cfg_str(node, "body_contains", "");
            cond.status_eq = cfg_int(node, "status_eq", -1);
            cond.case_sensitive = cfg_bool(node, "case_sensitive", false);
            return cond;
        };

        auto patterns_node = pt.get_child_optional("patterns");
        if (patterns_node) {
            // The key is authoritative even when the array is empty. Once
            // received, the built-in fallback pattern is disabled.
            has_patterns = true;
            for (const auto& item : patterns_node.get()) {
                const auto& pat_json = item.second;

                TracePattern pat;
                pat.id = cfg_str(pat_json, "id", "");
                if (pat.id.empty()) continue;

                pat.track = cfg_str(pat_json, "track", "*");
                pat.source = lowerCopy(cfg_str(pat_json, "source", "*"));
                if (pat.source != "*" && pat.source != "proxy" && pat.source != "otel")
                    continue;
                pat.window_sec = cfg_int(pat_json, "window_sec", 300);
                pat.min_events = cfg_int(pat_json, "min_events", 1);
                pat.cooldown_sec = cfg_int(pat_json, "cooldown_sec", 60);
                pat.pattern_severity = cfg_int(pat_json, "pattern_severity", 1);
                pat.order_strict = cfg_bool(pat_json, "order_strict", false);
                normalizeTracePattern(pat);

                auto conditions_node = pat_json.get_child_optional("conditions");
                if (!conditions_node) continue;

                for (const auto& cond_item : conditions_node.get()) {
                    TraceCondition cond = parse_condition(cond_item.second);
                    if (!cond.isEmpty())
                        pat.conditions.push_back(cond);
                }

                if (!pat.conditions.empty())
                    new_inventory.patterns.push_back(pat);
            }
        }

}
