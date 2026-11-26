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

#ifndef ALTPROBE_SURICATA_H
#define ALTPROBE_SURICATA_H
#include "ids_source.h"
#include "detection.h"
#include "http.h"
#include "proxy.h"
#include "logs.h"
#include <vector>
struct SuricataObservation {
    Event event;
    std::vector<Event> network;
    std::string ocsf;
    int class_uid = 0;
    bool inspect_http = false;
    Http http;
};
bool parseSuricataRecord(const std::string& line, const std::string& default_host,
    SuricataObservation& out, const std::string& default_consumer_id = "",
    const std::string& default_consumer_name = "");
class Suricata : public IdsSource {
    Proxy http_pipeline{"", ""};
public:
    Suricata() : IdsSource("suricata") {}
    bool processLine(const std::string& line) override;
};
extern boost::lockfree::spsc_queue<Http> q_modsec_suricata;
extern boost::lockfree::spsc_queue<std::string> q_logs_suricata;
extern boost::lockfree::spsc_queue<ApiCounterEvent> q_api_counters_suricata;
#endif
