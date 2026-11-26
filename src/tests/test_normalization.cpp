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

#include "proxy.h"
#include "classify.h"
#include "helpers.h"
#include "inventory.h"
#include <cassert>
#include <iostream>

int main() {
    Inventory classifier;
    Http observed;
    observed.url = "https://api.example/status/200?debug=true";
    assert(classifier.endpointPathForRequest(observed, TYPE_REST) == "/status/200");
    assert(classifier.routeTemplateForRequest(observed) == "/status/{id}");
    observed.url = "/api/abcdefghijklmnop";
    assert(classifier.endpointPathForRequest(observed, TYPE_REST) == "/api/abcdefghijklmnop");
    assert(classifier.routeTemplateForRequest(observed) == "/api/abcdefghijklmnop");
    observed.url = "/api/qrstuvwxyzabcdefghijklmnop";
    assert(classifier.routeTemplateForRequest(observed) == observed.url);
    observed.url = "/api/account-configuration-settings";
    assert(classifier.routeTemplateForRequest(observed) == observed.url);
    observed.url = "/api/AbCdEf0123456789_-AbCdEf0";
    assert(classifier.routeTemplateForRequest(observed) == "/api/{token}");
    observed.url = "/Admin//users/123/";
    assert(classifier.endpointPathForRequest(observed, TYPE_REST) == "/Admin//users/123/");
    assert(classifier.routeTemplateForRequest(observed) == "/Admin//users/{id}/");
    observed.url = " \t/Admin//users/123/\r\n";
    assert(classifier.endpointPathForRequest(observed, TYPE_REST) == "/Admin//users/123/");
    assert(classifier.routeTemplateForRequest(observed) == "/Admin//users/{id}/");
    observed.url = " \t\r\n";
    assert(classifier.endpointPathForRequest(observed, TYPE_REST) == "/");
    DiscoveryTarget inferred;
    inferred.type = "REST"; inferred.path = "/status/201"; inferred.method = "GET";
    inferred.state = "confirmed"; inferred.route_template = "/status/{id}";
    DiscoveryTarget exact;
    exact.type = "REST"; exact.path = "/status/200"; exact.method = "GET";
    exact.state = "unconfirmed"; exact.route_template = "/status/200";
    PolicyInventory previous;
    {
        std::lock_guard<std::mutex> guard(policy_inventory_mutex);
        previous = policy_inventory;
        policy_inventory.discovery_targets = {inferred, exact};
    }
    Endpoint endpoint;
    endpoint.type = "REST"; endpoint.path = "/status/200"; endpoint.method = "GET";
    endpoint.status = "unconfirmed";
    assert(classifier.shouldSendToAlertflex(TYPE_REST, true, endpoint, Event{}));
    endpoint.path = "/status/202";
    assert(!classifier.shouldSendToAlertflex(TYPE_REST, true, endpoint, Event{}));
    {
        std::lock_guard<std::mutex> guard(policy_inventory_mutex);
        policy_inventory = previous;
    }
    const std::string chat = R"({"model":"lab","messages":[{"role":"user","content":"hello"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"echo","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"ok"}]})";
    assert(classifier.classifyRequest("POST", "/v1/chat/completions", "content-type: application/json", chat) == TYPE_REST);
    assert(classifier.classifyRequest("POST", "/v1/chat/completions", "content-type: application/json",
        R"({"messages":[{"role":"user","content":"tool"}]})") == TYPE_REST);
    assert(classifier.classifyRequest("POST", "/invoke", "content-type: application/json",
        R"({"tool":"echo","arguments":{}})") == TYPE_MCP);
    assert(classifier.classifyRequest("POST", "/mcp", "content-type: application/json",
        R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}})") == TYPE_MCP);
    // Real sensor UTC timestamps must retain seconds for cooldown and flow joins.
    assert(parseTimeToMillis("2026-10-20T20:31:05.470094950Z") == 1792528265470ULL);
    assert(parseTimeToMillis("2026-10-20T20:31:12.470094950Z") == 1792528272470ULL);
    assert(parseTimeToMillis("2026-10-20T20:31:05Z") == 1792528265000ULL);
    assert(parseTimeToMillis("2026-10-20T23:31:05.470094950+03:00") == 1792528265470ULL);
    assert(parseTimeToMillis("2026-10-20T23:31:05.470094950+0300") == 1792528265470ULL);
    for (const auto& absent : {"", "-", " NULL ", "undefined", "0", "indef"})
        assert(!isMeaningfulIdentity(absent));
    assert(normalizeIdentity(" agent ") == "agent");
    // Anonymous gateway logs use "-" as the consumer sentinel and must not
    // collapse all explicit agent identities into one auth:gateway:- key.
    assert(authenticatedIdentityKey("apisix", "-").empty());
    assert(authenticatedIdentityKey("apisix", "indef").empty());
    assert(authenticatedIdentityKey("apisix", "agent-a") == "auth:apisix:agent-a");
    Proxy source("proxy", "PROXY");
    ProxyRecord p{};
    p.host_name = "host"; p.remote_addr = "10.0.0.1";
    p.event_ts_ms = 1700000000000;
    p.authenticated_gateway = "higress"; p.authenticated_principal = "agent-a";
    p.request_body = "ignore previous instructions";
    auto a = source.buildEventFromProxy(p);
    p.authenticated_principal = "agent-b";
    auto b = source.buildEventFromProxy(p);
    assert(makeKey(a) != makeKey(b) && a.agent_key != b.agent_key);
    assert(makeKey(a) == "auth:higress:agent-a");
    p.authenticated_gateway.clear(); p.authenticated_principal.clear();
    auto ip_a = source.buildEventFromProxy(p);
    p.remote_addr = "10.0.0.2";
    auto ip_b = source.buildEventFromProxy(p);
    assert(makeKey(ip_a) != makeKey(ip_b));
    assert(makeKey(ip_a) == "ip:host:10.0.0.1");
    assert(a.ts == p.event_ts_ms && b.ts == p.event_ts_ms);
    assert(a.signal == b.signal);
    std::cout << "PASS identity isolation and source timestamp preservation\n";
}
