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

#ifndef SINKS_H
#define	SINKS_H

#include "config.h"
#include "cobject.h"
#include <string>
#include <functional>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

class Sinks : public CObject {
public:

    
    // Format date for OpenSearch index (YYYY-MM-DD)
    std::string getDateIndex(const std::string& index);
    
    // Send HTTP/HTTPS request
    bool sendHttpRequest(
        bool is_https,
        const std::string& host,
        const std::string& port_str,
        const std::string& target,
        const std::string& method,
        const std::string& body,
        const std::string& auth_header,
        const std::map<std::string, std::string>& extra_headers,
        const std::string& content_type,
        bool tls_verify, const std::string& tls_ca_file,
        unsigned* status = nullptr, std::function<bool()> stop = {},
        std::chrono::milliseconds timeout = std::chrono::seconds(60));
    Sinks();
        
    // Send OCSF events to configured external sinks
    int sendOcsfToLogSinks(const std::string& log, int ocsf_type, const std::string& pipeline);
    int sendOcsfToLogSinks(const std::string& log, int ocsf_type, const std::string& pipeline, const std::string& source);

    // Splunk HEC accepts one JSON object per event. OCSF is embedded as the
    // event object, OTLP/JSON as the otel:trace sourcetype.
    int sendOcsfToSplunk(const std::string& log, int ocsf_type);
    int sendTraceToSplunk(const std::string& log, unsigned* status = nullptr, std::function<bool()> stop = {});

    // Graylog GELF HTTP input. One GELF 1.1 document per event: the raw OCSF or
    // OTLP/JSON record travels in full_message, classification in _fields.
    int sendOcsfToGraylog(const std::string& log, int ocsf_type,
                          const std::string& pipeline, const std::string& source);
    int sendTraceToGraylog(const std::string& log, unsigned* status = nullptr, std::function<bool()> stop = {});

};

#endif	/* SINKS_H */
