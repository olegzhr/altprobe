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

#ifndef ALTPROBE_OTLP_H
#define ALTPROBE_OTLP_H
#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"
#include "trace.h"
using OtlpRequest = opentelemetry::proto::collector::trace::v1::ExportTraceServiceRequest;
bool decodeOtlp(const std::string& body, bool json, OtlpRequest& out, std::string& error, size_t max_bytes = 0);
bool validateOtlp(const OtlpRequest& request, std::string& error);
std::string otlpJson(const OtlpRequest& request);
std::vector<TraceEvent> externalTraceEvents(const OtlpRequest& request);
std::string externalTriggeredTrace(const std::vector<TraceEvent>& chain, const TracePattern& pattern,
    const std::string& agent, long fired_at);
#endif
