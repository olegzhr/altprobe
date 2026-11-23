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

#include "proxy.h"
#include "helpers.h"
#include "logs.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>

int main() {
    CObject::host_name = "probe";
    CObject::af_url = "http://collector.internal:8080/api/v1";
    CObject::os_url = "";
    CObject::waf_status = CObject::llm_guard_enabled = false;
    Proxy proxy("proxy", "PROXY");
    for (const std::string host : {"application", "collector.internal:8080"}) {
        proxy.ClearRecords(); proxy.file_record.clear();
        std::string record = "{\"request_uri\":\"/api/v1/orders\",\"request_method\":\"GET\",\"http_host\":\"" + host + "\"}";
        std::strcpy(proxy.file_payload, record.c_str());
        assert(proxy.ParsJson(1) == 1);
    }
    proxy.fp = std::tmpfile(); assert(proxy.fp);
    std::string record = "{\"request_uri\":\"/mcp\",\"request_method\":\"POST\",\"request_body\":\"" +
            escapeJsonString(std::string(4096, '\\')) + "\",\"response_body\":\"" +
            escapeJsonString(std::string(8192, '\\')) + "\"}\n";
    std::fwrite(record.data(), 1, record.size(), proxy.fp); std::rewind(proxy.fp);
    assert(proxy.ReadFile() == 1 && proxy.file_record == record);
    assert(proxy.ParsJson(1) == 1);
    assert(proxy.ReadFile() == 0);
    // An incomplete tail must not be parsed or lost between polls.
    const std::string partial = "{\"request_uri\":\"/tail\"";
    auto position = std::ftell(proxy.fp);
    std::fwrite(partial.data(), 1, partial.size(), proxy.fp); std::fflush(proxy.fp);
    std::fseek(proxy.fp, position, SEEK_SET);
    assert(proxy.ReadFile() == 0);
    position = std::ftell(proxy.fp);
    std::fwrite("}\n", 1, 2, proxy.fp); std::fflush(proxy.fp); std::fseek(proxy.fp, position, SEEK_SET);
    assert(proxy.ReadFile() == 1 && proxy.file_record == partial + "}\n");
    // Oversized input is dropped once; the next valid record survives.
    position = std::ftell(proxy.fp);
    std::string oversized(Proxy::MAX_FILE_RECORD_BYTES + 10, 'x'); oversized += "\n{}\n";
    std::fwrite(oversized.data(), 1, oversized.size(), proxy.fp); std::fflush(proxy.fp);
    std::fseek(proxy.fp, position, SEEK_SET);
    int result = proxy.ReadFile(); if (!result) result = proxy.ReadFile();
    assert(result == 1 && proxy.file_record == "{}\n");
    std::fclose(proxy.fp); proxy.fp = nullptr;
    CObject::af_enable=true; CObject::os_enable=false;
    CObject::detection_enabled=false; CObject::trace_enabled=false;
    for (const auto& gateway : {"apisix", "envoy", "kong", "traefik", "higress"}) {
        proxy.ClearRecords(); proxy.ResetStream();
        const std::string origin=std::string(gateway)+":gateway-1";
        proxy.file_record="{\"request_uri\":\"/test-api/status\",\"request_method\":\"GET\","
            "\"remote_addr\":\"10.1.1.1\",\"request_id\":\"request-1\",\"gateway_origin_id\":\""+origin+"\"}";
        assert(proxy.ParsJson(1)==1);
        proxy.CreateLogRecord();
        ApiCounterEvent observation;
        assert(q_api_counters_proxy.pop(observation));
        assert(observation.gateway_origin_id==origin && observation.observation_id=="request-1");
    }
    std::cout << "PASS spoofed Host, long JSON lines, partial tails and oversized recovery\n";
}
