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

#include "log_delivery.h"
#include <cassert>
#include <iostream>

int main() {
    const std::vector<PendingLog> sent{{"A", "event A"}, {"B", "event B"}};
    std::vector<std::string> statuses;
    assert(parseLogAcknowledgement(R"({"ack_version":1,"records":[{"id":"B","status":"retry"},{"id":"A","status":"accepted"}]})", sent, statuses));
    assert(statuses[0] == "accepted" && statuses[1] == "retry");
    for (const auto& body : {
        R"({"processed":2,"failed":0})",
        R"({"ack_version":1,"records":[{"id":"A","status":"accepted"}]})",
        R"({"ack_version":1,"records":[{"id":"A","status":"accepted"},{"id":"A","status":"accepted"}]})",
        R"({"ack_version":1,"records":[{"id":"A","status":"accepted"},{"id":"C","status":"accepted"}]})",
        R"({"ack_version":1,"records":[{"id":"A","status":"accepted"},{"id":"B","status":"unknown"}]})",
        R"({"ack_version":"1","records":[]})"
    }) {
        assert(!parseLogAcknowledgement(body, sent, statuses));
        assert(statuses.empty());
    }
    assert(parseLogAcknowledgement(R"({"ack_version":1,"records":[{"id":"A","status":"rejected"},{"id":"B","status":"ignored"}]})", sent, statuses));
    assert(statuses[0] == "rejected" && statuses[1] == "ignored");
    std::cout << "PASS record-level log ACK validation\n";
}
