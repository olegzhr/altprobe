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

#ifndef CORRELATOR_H
#define CORRELATOR_H

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <boost/lockfree/spsc_queue.hpp>


#include "source.h"
#include "sinks.h"
#include "detection.h"

// ==============================
// EVENT CORRELATION AND FINDINGS
// ==============================
//
// Single-threaded consumer
// Lock-free ingestion queue
// Correlates events from Proxy, Modsec and LLM inspection into
// multi-stage API/AI attack chains using scoreAPI().
// Publishes HIGH+ findings to log sinks and the independent Alertflex incident queue.
//

class Correlator : public Source {
    friend struct CorrelatorIntegrationTest;

private:
    struct EmitState {
        long ts = 0;
        RiskLevel risk = LOW;
        uint32_t threat_mask = 0;
    };
    
    std::unordered_map<std::string, FeatureWindow> state;
    std::unordered_map<std::string, EmitState> last_emit;
    uint64_t processed_events = 0;
    long last_window_cleanup_ = 0;

    std::string resolveKey(const Event& e);
    bool shouldEmit(const std::string& key, long ts, RiskLevel risk, uint32_t threat_mask);
    void markEmit(const std::string& key, long ts, RiskLevel risk, uint32_t threat_mask);
    void cleanupEmitState(long now);

public:

    bool GetConfig(int mode) override {
        return Source::GetConfig(mode);
    }

    // ---- Main processing loop ----
    virtual bool Open() {
        if (!detection_enabled) source_status = false;
        return source_status;
    }
    virtual bool Go();
    
    bool emitFinding(
        const std::string& key,
        const Features& f,
        double score,
        RiskLevel risk,
        const Event& e);
};

// Each SPSC queue has exactly one producing module and one consumer (Correlator).
// New producers need their own queue; sharing a producer queue is not thread-safe.
extern boost::lockfree::spsc_queue<Event> q_suricata_correlator;
extern boost::lockfree::spsc_queue<Event> q_proxy_correlator;
extern boost::lockfree::spsc_queue<Event> q_modsec_correlator;
extern boost::lockfree::spsc_queue<Event> q_llm_correlator;

bool enqueueCorrelatorEvent(
    boost::lockfree::spsc_queue<Event>& queue,
    const Event& event,
    const char* source_name);

struct IncidentEnvelope {
    std::string id;
    std::string body; // immutable Alertflex incident envelope
};
extern std::atomic<bool> incident_ready;
extern boost::lockfree::spsc_queue<IncidentEnvelope> q_finding_incident;

#endif /* CORRELATOR_H */
