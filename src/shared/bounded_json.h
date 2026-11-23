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

#ifndef BOUNDED_JSON_H
#define BOUNDED_JSON_H
#include <string>
#include <vector>
#include <utility>

// Shared typed JSON model. Objects reject duplicate keys; arrays retain order.
struct Json {
    char kind = 'n';
    std::string text;
    std::vector<std::pair<std::string, Json>> children;
    const Json* get(const std::string& key) const {
        if (kind != 'o') return nullptr;
        for (const auto& item : children) if (item.first == key) return &item.second;
        return nullptr;
    }
    std::string string(const std::string& key) const {
        auto value = get(key);
        return value && value->kind == 's' ? value->text : "";
    }
};
bool parseBoundedJson(const std::string& text, Json& out,
    size_t max_bytes = 262144, size_t max_nodes = 4096);
std::string canonicalJson(const Json& value);
#endif
