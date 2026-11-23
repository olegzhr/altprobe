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

#include "detection.h"
#include "correlator.h"
#include "proxy.h"
#include <cassert>
#include <iostream>
#include <thread>

static Event event(long ts, SignalType signal) {
    Event e; e.ts=ts; e.source=3; e.signal=signal; e.src_ip="10.1.1.1"; return e;
}
struct CorrelatorIntegrationTest {
    static void idleCleanup() {
        CObject::detection_enabled=true;
        CObject::gosleep_interval=0; CObject::entity_ttl=1;
        Correlator c;
        const long now=eventTimeMillis(0);
        c.state["old"].add(event(now-2000,SIG_PROMPT_INJECTION),now-2000,1000);
        c.Go(); assert(c.state.empty());
    }
};
int main() {
    FeatureWindow window;
    window.add(event(1000,SIG_PROMPT_INJECTION),1000,90000);
    for(long t=2000;t<=200000;t+=1000) window.add(event(t,SIG_MCP_TOOL_CALL),t,90000);
    assert(window.features.prompt_injection_count==0);
    assert(!hasThreatEvidence(window.features));
    assert(window.features.first_seen>=110000);
    assert(!window.features.ordered_prompt_tool);
    assert(!window.expire(290001,90000));
    assert(window.features.tool_call_count==0 && window.features.stage_mask==0);
    FeatureWindow late;
    late.add(event(3000,SIG_MCP_TOOL_CALL),3000,90000);
    late.add(event(2000,SIG_PROMPT_INJECTION),3000,90000);
    assert(late.features.timeline.front().ts==2000);
    assert(late.features.ordered_prompt_tool);
    late.expire(92500,90000);
    assert(late.features.prompt_injection_count==0 && !late.features.ordered_prompt_tool);
    Event body=event(1000,SIG_TOOL_ABUSE);
    body.request_body="bash shell litellm jsonrpc tools/call";
    Features direct; updateFeatures(direct,body);
    FeatureWindow compact; compact.add(body,1000,90000);
    assert(compact.features.stage_mask==direct.stage_mask);
    assert(compact.features.ai_gateway_context_count==direct.ai_gateway_context_count);
    assert(scoreAPI(compact.features)==scoreAPI(direct));
    for(size_t n=0;n<FeatureWindow::max_events+2;++n) compact.add(body,1000,90000);
    assert(compact.size()==FeatureWindow::max_events);
    for(bool inbound : {false,true}) {
        CObject::detection_enabled=inbound;
        Correlator c; assert(c.Open()==inbound);
    }
    CorrelatorIntegrationTest::idleCleanup();
    // Close may signal a worker but must leave its handles/buffers untouched.
    CObject::proxy_log_status=true; CObject::gosleep_interval=100;
    Proxy p("proxy", "PROXY"); p.fp=std::tmpfile(); assert(p.fp);
    FILE* owned=p.fp;
    std::thread worker([&] { while(p.Go()) {} });
    p.Close(); worker.join();
    assert(p.fp==owned && !p.source_status);
    std::cout<<"PASS feature expiry, late events, compact predicates, idle cleanup, inbound gate and Proxy ownership\n";
}
