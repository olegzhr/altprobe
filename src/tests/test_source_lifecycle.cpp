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

#include "openshell.h"
#include "scanner.h"
#include "correlator.h"
#include <cassert>
#include <future>
#include <thread>

int main() {
    CObject::af_enable = CObject::os_enable = CObject::splunk_enable = CObject::graylog_enable = false;
    CObject::detection_enabled = CObject::trace_enabled = CObject::llm_guard_enabled = false;
    Openshell source;
    const std::string network = R"({"class_uid":4001,"action_id":1,"time":1234,
        "device":{"hostname":"node-a","container":{"uid":"c1","name":"agent"}},
        "actor":{"process":{"name":"curl","pid":42,"parent_pid":40}},
        "src_endpoint":{"ip":"10.0.0.2","port":12345},
        "dst_endpoint":{"ip":"1.2.3.4","port":443,"domain":"api.openai.com"},
        "connection_info":{"protocol_name":"tcp"},"firewall_rule":{"name":"allow"}})";
    assert(source.processLine(network));
    auto denied = network; denied.replace(denied.find("\"action_id\":1"), 13, "\"action_id\":2");
    assert(source.processLine(denied));
    assert(source.processLine(R"({"class_uid":4001,"action_id":1,"dst_endpoint":{"ip":false}})"));

    Scanner scanner; scanner.scan_interval = 60;
    std::promise<void> entered, completed;
    auto ready = entered.get_future(); auto done = completed.get_future();
    std::thread worker([&] { entered.set_value(); scanner.Go(); completed.set_value(); });
    ready.wait();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    scanner.Close();
    assert(done.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    worker.join();
}
