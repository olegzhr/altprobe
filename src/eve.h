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

#ifndef EVE_H
#define EVE_H

#include <boost/property_tree/ptree.hpp>
#include <string>
#include <chrono>
#include <ctime>

using namespace std;
namespace bpt = boost::property_tree;

class Eve {
public:
    Eve();
    ~Eve();

    // Main function to parse HTTP request
    string getHeaders(const string& http_request, const string& http_method, const string& url, const string& version);
    // Helper functions
    bpt::ptree parseHeaders(istringstream& stream, string& content_type, string& content_encoding);

    // Utilities
    static bool isBase64(const string& str);
    static string base64Decode(const string& encoded_string);

};

#endif // EVE_H
