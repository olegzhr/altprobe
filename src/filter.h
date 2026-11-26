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

// filter.h
#ifndef FILTER_H
#define FILTER_H

#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <memory>
#include <chrono>
#include "source.h"

using namespace std;

#include "inventory_types.h"

// ==============================
// GLOBAL SNAPSHOTS
// ==============================
extern PolicyInventory policy_inventory;
extern std::mutex policy_inventory_mutex;
extern std::atomic<uint64_t> policy_inventory_version;

// ==============================
// FILTER CLASS
// ==============================
class Filter : public Source {
    friend struct InventoryIntegrationTest;

public:
    Filter() {}

    virtual bool Open() {
        if (!af_enable) source_status = false;
        return source_status;
    }
    virtual bool Go();

    // Get inventory data
    static PolicyInventory getInventory();
    static std::shared_ptr<const PolicyInventory> getInventorySnapshot();
    static std::vector<Endpoint> getEndpoints();
    static std::vector<TracePattern> getPatterns();
    static uint64_t getInventoryVersion();

    // True once alertflex-ctrl has delivered an inventory carrying a
    // "patterns" key (even an empty array). After that the built-in fallback
    // pattern must not be re-injected, so disabling all triggers actually
    // stops trace emission.
    static bool patternsManaged();

private:
    bool fetchInventory();

    // ---- HTTP METHOD ----
    bool sendHttpRequest(
        bool is_https,
        const std::string& host,
        const std::string& port,
        const std::string& target,
        const std::string& method,
        const std::string& body,
        const std::string& auth,
        const std::vector<std::string>& headers,
        const std::string& content_type,
        std::string* response
    );
};

#endif /* FILTER_H */
