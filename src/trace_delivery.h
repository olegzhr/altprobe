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

#ifndef ALTPROBE_TRACE_DELIVERY_H
#define ALTPROBE_TRACE_DELIVERY_H
#include "source.h"
#include <memory>

// A successful enqueue means the immutable payload and directory entry were
// fsync'd. Each destination has independent quotas, retry state and worker.
class TraceDelivery : public Source {
public:
    TraceDelivery();
    ~TraceDelivery() override;
    bool Open() override;
    bool Go() override;
    void Close() override;
    bool alertflex(const std::string& body);
    bool opensearch(const std::string& body);
    bool stageSinks(const std::string& body, size_t& next);
    bool incoming(const std::string& body);
    std::vector<std::string> incomingIds();
    bool readIncoming(const std::string& id, std::string& body);
    bool finishIncoming(const std::string& id);
    bool ready() const;
    bool HasFailed() const;
private:
    bool splunk(const std::string& body);
    bool graylog(const std::string& body);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
extern TraceDelivery traceDelivery;
std::string traceDigest(const std::string& text);
#endif
