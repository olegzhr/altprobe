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

#pragma once
#include <string>
#include <vector>
struct HttpListenerConfig {
    bool enabled = false;
    std::string bind_host = "127.0.0.1";
    int port = 8181;
    int workers = 4;
    int max_requests = 256;
    int max_body_bytes = 262144;
    int request_timeout_ms = 2000;
    std::string tls_cert, tls_key, tls_ca;
    std::vector<std::string> trusted_peers{"127.0.0.1", "::1"};
};

bool listenerPeerAllowed(const std::string&, const HttpListenerConfig&);
std::string listenerReadFile(const std::string&);
