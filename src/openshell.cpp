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
#include "ids_json.h"

bool Openshell::processLine(const std::string& raw) {
    // Supervisor stderr: "2026-... OCSF-JSON {...}", JSONL: raw object.
    std::string line = raw;
    auto marker = line.find("OCSF-JSON");
    if (marker != std::string::npos) {
        auto brace = line.find('{', marker);
        if (brace == std::string::npos) return false;
        line = line.substr(brace);
    } else {
        auto brace = line.find('{');
        if (brace == std::string::npos) return false;
        line = line.substr(brace);
    }
    const auto key = line.find("\"class_uid\"");
    if (key == std::string::npos) { SysLog((char*)"[OpenShell] no class key"); return false; }
    const auto colon = line.find(':', key);
    if (colon == std::string::npos) return false;
    long class_uid = 0;
    try { class_uid = std::stol(line.substr(colon + 1)); } catch (...) { return false; }
    if (class_uid < 0) return false;

    // OpenShell already emits complete OCSF. If the source has no per-agent
    // field, stamp the configured Alertflex agent id/name without changing the
    // native record. An existing agent object wins.
    if (!consumerId().empty()) {
        Json doc;
        if (parseBoundedJson(line, doc, 8 * 1024 * 1024, 65536) && doc.kind == 'o' && !doc.get("agent")) {
            std::string prefix = "\"agent\":{\"id\":" + jsonQuote(consumerId());
            if (!consumerName().empty()) prefix += ",\"name\":" + jsonQuote(consumerName());
            prefix += "},";
            const auto brace = line.find('{');
            if (brace != std::string::npos) line.insert(brace + 1, prefix);
        }
    }

    // OpenShell already emits complete OCSF. Forward the original object
    // unchanged; only the sink indexing decision uses class_uid.
    if (LogProcessingEnabled()) {
        sk.sendOcsfToLogSinks(line, static_cast<int>(class_uid), "indef", "openshell");
    }
    return true;
}
