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

#ifndef INVENTORY_H
#define INVENTORY_H

#include <string>
#include <vector>
#include <boost/property_tree/ptree.hpp>

#include "detection.h"
#include "filter.h"
#include "http.h"

#include "request_classifier.h"

// Matches observed REST/MCP/A2A operations to the current discovery baseline.
// Enrichment describes known objects and drift; it does not make access decisions.
class Inventory : public RequestClassifier {
public:
    Inventory() = default;
    ~Inventory() = default;
    
    bool matchEndpoint(const Http& http, RequestType type, Endpoint& out_ep);
    bool isA2aTaskActivity(const Http& http, const Event& e) const;

    void enrich(Event& e, bool inspect_request = true);

    bool isMcpSignal(SignalType signal) const;
    bool canInventoryOverride(SignalType signal) const;
    bool hasMcpDrift(const Event& e) const;
    bool shouldSendToAlertflex(RequestType type,
        bool endpoint_matched,
        const Endpoint& endpoint,
        const Event& e) const;


    bool endpointKnown(const PolicyInventory& inventory, const Event& e) const;
    bool objectKnown(const PolicyInventory& inventory, const Event& e) const;
    
private:
};

#endif

