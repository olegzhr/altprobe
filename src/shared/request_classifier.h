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
#include "http.h"
#include <boost/property_tree/ptree.hpp>
#include <vector>
enum RequestType { TYPE_UNKNOWN = 0, TYPE_REST = 1, TYPE_MCP = 2, TYPE_A2A = 3 };
class RequestClassifier {
public:
    RequestType classifyRequest(const std::string&, const std::string&, const std::string&, const std::string&);
    std::string endpointPathForRequest(const Http&, RequestType) const;
    std::string routeTemplateForRequest(const Http&) const;
    std::string endpointMethodForRequest(const Http&, RequestType) const;
protected:
    static std::string lowerCopy(const std::string&);
    static bool parseJson(const std::string&, boost::property_tree::ptree&);
    static std::string getJsonString(const boost::property_tree::ptree&, const std::vector<std::string>&);
    static std::string extractJsonRpcMethod(const std::string&);
    static std::string extractA2aOperation(const Http&);
    static std::string normalizePath(const std::string&, bool);
    static std::string normalizeSegment(const std::string&);
    static bool sameEndpointPath(const std::string&, const std::string&);
};
