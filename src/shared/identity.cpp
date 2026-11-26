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

#include "gateway_identity.h"
#include "detection.h"
#include <algorithm>
#include <cctype>

std::string normalizeIdentity(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    std::string result = value.substr(first, last - first + 1);
    std::string lower = result;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower == "-" || lower == "null" || lower == "undefined" || lower == "0" || lower == "indef") return "";
    return result;
}

bool isMeaningfulIdentity(const std::string& value) { return !normalizeIdentity(value).empty(); }

std::string authenticatedIdentityKey(const std::string& gateway, const std::string& principal) {
    if ((!isObservedGateway(gateway) && gateway != "envoy" && gateway != "alertflex") || principal.empty() || principal.size() > 3600) return "";
    // Gateway loggers use "-" (and similar sentinels) when no authenticated
    // consumer exists. Treat those as anonymous so the source IP fallback is
    // used instead of a shared auth:gateway:- key.
    if (principal == "-" || principal == "indef" || principal == "unknown") return "";
    // Preserve the authenticated subject exactly; do not trim or lowercase it.
    if (std::isspace(static_cast<unsigned char>(principal.front())) || std::isspace(static_cast<unsigned char>(principal.back()))) return "";
    for (unsigned char c : principal) if (c < 32 || c == 127) return "";
    return "auth:" + gateway + ":" + principal;
}

std::string makeKey(const Event& e) {
    if (const auto consumer = normalizeIdentity(e.consumer_id); !consumer.empty())
        return "consumer:" + consumer;

    auto authenticated = authenticatedIdentityKey(e.authenticated_gateway, e.authenticated_principal);
    if (!authenticated.empty()) return authenticated;

    // Identity model: auth key, otherwise the observed source IP. No headers,
    // process names, session ids or time buckets are identity inputs.
    if (!e.src_ip.empty())
        return "ip:" + e.host_id + ":" + normalizeIdentity(e.src_ip);

    return "ip:" + e.host_id + ":unknown";
}

