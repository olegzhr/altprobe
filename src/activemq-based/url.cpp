/*
 *   Copyright 2021 Oleg Zharkov
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

#include "url.h"

URLComponents parseURL(const std::string& url) {
    URLComponents components;
    components.port = 80; // Default HTTP port

    // Find the protocol separator "://"
    size_t protocolEnd = url.find("://");
    if (protocolEnd == std::string::npos) {
        throw std::invalid_argument("Invalid URL: Missing protocol");
    }

    // Extract the host and path part
    size_t hostStart = protocolEnd + 3; // Start after "://"
    size_t pathStart = url.find('/', hostStart);

    // Extract the host
    if (pathStart == std::string::npos) {
        components.host = url.substr(hostStart);
        components.path = "/"; // Default path
    } else {
        components.host = url.substr(hostStart, pathStart - hostStart);
        components.path = url.substr(pathStart);
    }

    // Check if the host contains a port
    size_t portSeparator = components.host.find(':');
    if (portSeparator != std::string::npos) {
        // Extract the port
        components.port = std::stoi(components.host.substr(portSeparator + 1));
        // Remove the port from the host
        components.host = components.host.substr(0, portSeparator);
    }

    return components;
}