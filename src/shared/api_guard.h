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

#ifndef API_GUARD_H
#define API_GUARD_H

#include <memory>
#include <string>
#include <vector>
#include "detection.h"

class ApiGuard {
public:
    ApiGuard();
    // Invalid configurations retain the previous immutable ruleset.
    bool load(const std::string& path);
    SignalType classifyHttpMcpSignal(const std::string& method, const std::string& url,
        const std::string& headers, const std::string& body, const std::string& response,
        GuardMatch* detail = nullptr) const;
    SignalType classifyRestSignal(const std::string& method, const std::string& url,
        const std::string& headers, const std::string& body, const std::string& response,
        GuardMatch* detail = nullptr) const;

private:
    struct Rule {
        std::string id, kind, reason;
        SignalType signal = SIG_UNKNOWN;
        std::vector<std::string> fields;
        std::vector<std::string> tools; // Optional exact tools/call name selector.
        // Every group must match; terms within a group are alternatives.
        std::vector<std::vector<std::string>> all;
        size_t window = 160;
        int confidence = 80;
    };
    struct Ruleset {
        std::string version = "builtin-v2";
        std::vector<Rule> rules;
    };
    std::shared_ptr<const Ruleset> ruleset;
    static Ruleset defaults();
    SignalType inspect(const std::string& method, const std::string& url,
        const std::string& headers, const std::string& body, const std::string& response,
        bool rest_only, GuardMatch* detail) const;
};

extern ApiGuard apiGuard;
// Accept raw HTTP lines or the structured header representation used by
// Proxy/Modsec. Does not recover redacted header values.
bool apiGuardHeaderLines(const std::string& input, std::string& output);
#endif

