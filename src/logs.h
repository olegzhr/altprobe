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

#ifndef LOGS_H
#define LOGS_H

#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <cstddef>
#include <boost/lockfree/spsc_queue.hpp>

#include "source.h"
#include "log_delivery.h"

#define MAX_BATCH_SIZE 262144  // 256 KB

// Hard bounds also apply during an arbitrarily long controller outage.
constexpr std::size_t MAX_PENDING_LOGS = 4096;
constexpr std::size_t MAX_PENDING_LOG_BYTES = 16 * 1024 * 1024;
constexpr std::size_t MAX_PENDING_LOG_RECORD_BYTES = 1024 * 1024;
constexpr std::size_t MAX_COUNTER_KEYS = 4096;
constexpr std::size_t MAX_COUNTER_KEY_PART_BYTES = 1024;

struct ApiCounterEvent {
    std::string path, method, type, gateway_origin_id, observation_id;
    long last_observed_ms = 0;
};

// Collects discovery telemetry and API counters for the Alertflex controller.
// Record-level ACKs govern retries. Pending data is bounded; overflow drops new
// observations with a diagnostic, preserving already pending records and IDs.
class Logs : public Source {
public:

    std::string rec;
    std::vector<PendingLog> logs_list;
    std::map<std::string, ApiCounterEvent> counters_list;

    virtual bool Open() {
        if (!af_enable) source_status = false;
        return source_status;
    }
    virtual bool Go();
    
    void ProcessLogs();
    void ProcessCounters();

    bool sendCompressedBatch(const std::string& json, std::string* response = nullptr);
    int sendBatchToAF(const std::string& compressed, std::string* response = nullptr);
    bool quarantineRecord(const PendingLog& record);
    bool sendCountersToAF(const std::vector<ApiCounterEvent>& counters);
    static std::string jsonEscape(const std::string& value);

    bool sendHttpRequest(
        bool is_https,
        const std::string& host,
        const std::string& port,
        const std::string& target,
        const std::string& method,
        const std::string& body,
        const std::string& auth,
        const std::map<std::string, std::string>& headers,
        const std::string& content_type,
        std::string* response = nullptr
    );
};

extern boost::lockfree::spsc_queue<ApiCounterEvent> q_api_counters_proxy;

#endif
