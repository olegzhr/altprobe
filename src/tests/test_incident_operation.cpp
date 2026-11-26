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

// Exercise the serialized native incident, not a copy of the formatter.
#include "correlator.h"
#include "json_wire.h"
#include <cassert>
#include <iostream>

static void operation(Event event, const std::string& expected) {
    event.ts = event.observed_ts = eventTimeMillis(0);
    event.source = 3;
    event.signal = SIG_PROMPT_INJECTION;
    Features features{};
    updateFeatures(features, event);
    Correlator correlator;
    assert(correlator.emitFinding("auth:alertflex:test-agent", features, 0.9, HIGH, event));
    IncidentEnvelope envelope;
    assert(q_finding_incident.pop(envelope));
    Json doc;
    assert(parseBoundedJson(envelope.body, doc));
    const Json* finding = doc.get("finding");
    assert(finding && finding->get("api"));
    assert(finding->get("api")->string("operation") == expected);
    assert(finding->get("metadata")->string("correlation_uid") == "auth:alertflex:test-agent");
    assert(q_finding_incident.empty()); // Exactly one immutable incident envelope.
}

int main() {
    CObject::run_mode = 2;
    CObject::af_enable = CObject::os_enable = CObject::log_debug = false;
    CObject::incident_enabled = true;
    CObject::project_id = "operation-test";
    CObject::asset_name = "operation-asset";
    CObject::host_name = "operation-probe";
    incident_ready.store(true);

    Event e{};
    e.protocol = "http"; e.http_method = "POST";
    e.url = "/mcp/case-a?trace=ignored";
    for (const auto& method : {"initialize", "notifications/initialized", "tools/list", "tools/call",
                              "resources/list", "resources/read", "prompts/list", "prompts/get", "ping"}) {
        e.mcp_method = method;
        operation(e, std::string(method) + " /mcp/case-a");
    }
    e.url = "https://gateway.example/mcp/case-b?trace=ignored";
    operation(e, "ping /mcp/case-b"); // Same URL normalization as inventory.
    e.mcp_method.clear(); e.a2a_operation = "message/send"; e.url = "/a2a/agent";
    operation(e, "message/send /a2a/agent");
    e.a2a_operation = "tasks/get";
    operation(e, "tasks/get /a2a/agent");
    e.a2a_operation.clear(); e.url = "/orders/123";
    operation(e, "POST /orders/123"); // Concrete route, never a guessed template.
    e.http_method = "GET"; e.url = "/health";
    operation(e, "GET /health");
    e.mcp_method = "-"; e.a2a_operation = "-";
    operation(e, "GET /health"); // Absent Envoy metadata is not an operation.
    e.mcp_method.clear();
    operation(e, "GET /health");
    e.a2a_operation.clear();
    e.url.clear(); e.mcp_method = "tools/call";
    operation(e, "tools/call"); // stdio: no fictitious HTTP endpoint.
    e.mcp_method.clear(); e.http_method.clear(); e.mcp_object_name = "read_record";
    operation(e, "read_record");
    incident_ready.store(false);
    std::cout << "PASS 18 native MCP/A2A/REST/stdio incident operation contracts\n";
}
