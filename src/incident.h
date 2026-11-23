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

#ifndef INCIDENT_H
#define INCIDENT_H
#include "source.h"
#include "correlator.h"
#include <deque>
#include <optional>
#include <unordered_set>

// Delivers immutable findings to Alertflex from a bounded disk-backed spool.
// Records are removed only after a matching acknowledgement; permanent failures
// are retained as .rejected files. Gateway decisions belong to ctrlprobe.
// The in-memory producer queue is not durable until persist() succeeds.
class Incident : public Source {
public:
    bool Open() override;
    void Close() override;
    bool Go() override;
    ~Incident() override;
private:
    struct Pending {
        IncidentEnvelope incident;
        unsigned attempts = 0;
        std::chrono::steady_clock::time_point due{};
    };
    std::atomic<bool> opened_{false};
    bool https_ = true;
    std::string host_, port_, authority_, target_, project_, token_;
    int directory_ = -1, timeout_ = 5000;
    size_t capacity_ = 512, records_ = 0;
    std::chrono::steady_clock::time_point last_warning_{};
    std::deque<Pending> pending_;
    std::optional<IncidentEnvelope> unstaged_;
    std::unordered_set<std::string> ids_;
    bool valid(const IncidentEnvelope& incident) const;
    bool persist(const IncidentEnvelope& incident);
    void load();
    void deliver(Pending& pending, bool& finished);
};
#endif
