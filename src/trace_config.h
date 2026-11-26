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

#ifndef ALTPROBE_TRACE_CONFIG_H
#define ALTPROBE_TRACE_CONFIG_H
#include "listener_transport.h"
#include <cstdint>

struct TraceConfig {
    std::string mode = "internal"; // internal | external | off
    std::string spool_dir = "/var/lib/altprobe/traces";
    int max_pending = 4096;
    uint64_t max_spool_bytes = 268435456;
    int timeout_ms = 5000;
    bool os_ocsf = true, os_http = true, os_otel = true;
    HttpListenerConfig collector;
    int http_port = 4318, grpc_port = 4317; // 0 disables one transport
    std::string bearer_token;
};
const TraceConfig& traceConfig();
bool loadTraceConfig(int mode, std::string& error, const std::string& file = "");
#endif
