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

#ifndef ALTPROBE_LOG_DELIVERY_H
#define ALTPROBE_LOG_DELIVERY_H
#include "bounded_json.h"
#include <map>
#include <string>
#include <vector>

struct PendingLog {
    std::string id;
    std::string event; // Immutable raw OCSF JSON; ID is retained across retries.
};

// Reject the entire ACK if it is ambiguous. Receipt-based server deduplication
// makes retrying records safe when the response is missing or malformed.
inline bool parseLogAcknowledgement(const std::string& body,
        const std::vector<PendingLog>& records, std::vector<std::string>& statuses) {
    Json root;
    statuses.clear();
    if (!parseBoundedJson(body, root, 1024 * 1024, 100000) || root.kind != 'o') return false;
    auto version = root.get("ack_version");
    auto acknowledgements = root.get("records");
    if (!version || version->kind != 'd' || version->text != "1" ||
            !acknowledgements || acknowledgements->kind != 'a' ||
            acknowledgements->children.size() != records.size()) return false;
    std::map<std::string, size_t> expected;
    for (size_t i = 0; i < records.size(); ++i)
        if (!expected.emplace(records[i].id, i).second) return false;
    std::vector<std::string> result(records.size());
    for (const auto& entry : acknowledgements->children) {
        const auto& ack = entry.second;
        auto found = expected.find(ack.string("id"));
        const auto status = ack.string("status");
        if (ack.kind != 'o' || found == expected.end() || !result[found->second].empty() ||
                (status != "accepted" && status != "ignored" && status != "retry" && status != "rejected")) return false;
        result[found->second] = status;
    }
    statuses = std::move(result);
    return true;
}
#endif
