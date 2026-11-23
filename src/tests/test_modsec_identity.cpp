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

#include "modsec.h"
#include "proxy.h"
#include <cassert>
#include <iostream>

int main() {
    CObject::os_enable = CObject::af_enable = CObject::log_debug = false;
    CObject::detection_enabled = true;
    CObject::host_name = "probe-config";
    CObject::waf_status = true;
    CObject::llm_guard_enabled = false;
    CObject::gateway_type = "higress";
    std::string error;
    Proxy proxy("proxy", "PROXY");
    const std::string record = R"({"remote_addr":"10.0.0.1","consumer_name":"agent-A","request_method":"GET","request_uri":"/attack","http_host":"127.0.0.1","server_port":80})";
    std::strcpy(proxy.file_payload, record.c_str());
    assert(proxy.ParsJson(1) == 1);
    Http staged;
    assert(q_modsec_proxy.pop(staged));
    assert(staged.authenticated_principal == "agent-A" && staged.authenticated_gateway == "higress");
    assert(staged.identity_host == "probe-config");
    Modsec m;
    assert(m.rules->load("SecRuleEngine On\nSecRule REQUEST_URI \"@contains attack\" \"id:942100,phase:1,log,pass,msg:'identity regression'\"\n") >= 0);
    for (const std::string principal : {"agent-A", "agent-B", ""}) {
        m.http.Reset();
        m.http.client_ip = "10.0.0.1"; m.http.identity_host = "gateway-host";
        m.http.server_ip = "127.0.0.1"; m.http.server_port = 80;
        m.http.http_method = "GET"; m.http.url = "/attack"; m.http.version = "HTTP/1.1";
        m.http.authenticated_gateway = "higress"; m.http.authenticated_principal = principal;
        m.http.request_id = "operation"; m.http.session_id = "session";
        m.http.request_truncated = true;
        m.processHttpRequest("10.0.0.1", "127.0.0.1", 80, "/attack", "GET", "HTTP/1.1", {}, "");
        Event e;
        assert(q_modsec_correlator.pop(e));
        assert(makeKey(e) == (principal.empty() ? "ip:gateway-host:10.0.0.1" : "auth:higress:" + principal));
        assert(e.operation_id == "operation" && e.session_id == "session" && e.request_truncated);
        while (q_modsec_correlator.pop(e)) { }
    }
    std::cout << "PASS WAF principal isolation and IP host fallback\n";
}
