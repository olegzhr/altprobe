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

#ifndef HTTP_H
#define	HTTP_H

#include <string>

using namespace std;

class Http {
public:
    long event_ts_ms = 0;
    string client_ip;
    string identity_host;
    string request_id;
    string session_id, agent_key, trace_id, span_id, authenticated_principal, authenticated_gateway;
    string identity_namespace;
    string server_ip;
    unsigned int server_port;
    string http_method;
    string url;
    string version;
    unsigned int  status;
    unsigned int  duration;
    string request_headers;
    string request_body;
    string response_body;
    bool request_truncated = false, response_truncated = false;
    bool request_missing = false, response_missing = false;
    size_t request_original_size = 0, response_original_size = 0;
    
    void Reset() {
        event_ts_ms = 0;
        client_ip.clear();
        identity_host.clear();
        request_id.clear();
        session_id.clear(); agent_key.clear(); trace_id.clear(); span_id.clear();
        authenticated_principal.clear(); authenticated_gateway.clear();
        identity_namespace.clear();
        server_ip.clear();
        server_port = 0;
        http_method.clear();
        version.clear();
        url.clear();
        status = 0;
        duration = 0;
        request_headers.clear();
        request_body.clear();
        response_body.clear();
        request_truncated = response_truncated = request_missing = response_missing = false;
        request_original_size = response_original_size = 0;
    }
};

#endif	/* HTTP_H */



