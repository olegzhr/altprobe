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
#include <cassert>
#include <stdexcept>

static const std::string prefix = R"({"asset":"gateway","projectId":"project","policyTargetVersion":2,"agentAuthVersion":1,"requireAgentKey":true,"endpoints":[],"agents":[)";

int main() {
    PolicyInventory snapshot;
    bool managed = false;
    const std::string discovered = R"({"id":"7","assetName":"gateway","correlationUid":"","blockStatus":"active"})";
    // Discovery without UID is valid. It grants no authenticated identity.
    decodeInventory(prefix + discovered + "],\"patterns\":[]}", "gateway", "project", true, snapshot, managed);
    assert(snapshot.agents.size() == 1 && snapshot.agents[0].correlationUid.empty());
    assert(snapshot.agents[0].bindingAssetName.empty() && managed);

    const std::string credential = R"({"id":"7","assetName":"gateway","correlationUid":"auth:apisix:consumer-7","blockStatus":"active","keyId":")" +
        std::string(32, 'a') + R"(","keyHash":")" + std::string(64, 'b') + R"(","keyStatus":"active"})";
    decodeInventory(prefix + credential + "]}", "gateway", "project", true, snapshot, managed);
    assert(snapshot.agents[0].keyHash.size() == 64 && snapshot.agents[0].bindingAssetName == "gateway");
    const auto epoch = credential.substr(0, credential.size() - 1) + ",\"keyExpiresAt\":0}";
    decodeInventory(prefix + epoch + "]}", "gateway", "project", true, snapshot, managed);
    assert(snapshot.agents[0].keyExpiresAt && *snapshot.agents[0].keyExpiresAt == 0);
    // The collector uses the same parser but never retains authentication hashes.
    decodeInventory(prefix + credential + "]}", "gateway", "project", false, snapshot, managed);
    assert(snapshot.agents[0].keyHash.empty() && snapshot.agents[0].keyId.empty());
    // Strict expiry typing; malformed values cannot become a non-expiring key.
    for (const auto& invalid_expiry : {"\"tomorrow\"", "1.5", "9223372036854775808"}) {
        bool failed = false;
        const auto row = credential.substr(0, credential.size() - 1) + ",\"keyExpiresAt\":" + invalid_expiry + "}";
        try { decodeInventory(prefix + row + "]}", "gateway", "project", true, snapshot, managed); }
        catch (const std::exception&) { failed = true; }
        assert(failed);
    }
    decodeInventory(prefix + credential + "]}", "gateway", "project", false, snapshot, managed);
    assert(snapshot.agents[0].correlationUid == "auth:apisix:consumer-7");

    for (const auto& invalid : {
            prefix + credential + "," + credential + "]}",
            prefix + R"({"id":"7","assetName":"gateway","bindingAssetName":"gateway","correlationUid":"","blockStatus":"active"}]})",
            prefix + R"({"id":"7","assetName":"another","correlationUid":"","blockStatus":"active"}]})"}) {
        bool failed = false;
        try { decodeInventory(invalid, "gateway", "project", true, snapshot, managed); }
        catch (const std::exception&) { failed = true; }
        assert(failed);
    }
    bool wrong_project = false;
    try { decodeInventory(prefix + discovered + "]}", "gateway", "other", true, snapshot, managed); }
    catch (const std::exception&) { wrong_project = true; }
    assert(wrong_project);
}
