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

#include <boost/property_tree/json_parser.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <algorithm>
#include "eve.h"
#include "helpers.h"

namespace bai = boost::archive::iterators;

Eve::Eve() = default;
Eve::~Eve() = default;

string Eve::getHeaders(const string& http_request, const string& http_method, const string& url, const string& version) {
    bpt::ptree parsed_payload;
    istringstream stream(http_request);

    // Parse headers
    string content_type, content_encoding;
    bpt::ptree headers_array = parseHeaders(stream, content_type, content_encoding);

    // Store headers separately
    parsed_payload.add_child("headers_raw", headers_array);

    // Prepare final output
    bpt::ptree output;

    // Add headers as array
    headers_array.clear();
    for (auto& h : parsed_payload.get_child("headers_raw")) {
        headers_array.push_back(std::make_pair("", h.second));
    }
    output.add_child("http_headers", headers_array);
    output.put("http_method", http_method); 
    output.put("url", url); 
    output.put("version", version); 

    // Write JSON in one line
    std::ostringstream oss;
    boost::property_tree::write_json(oss, output, false); // false disables pretty-print

    std::string json_str = oss.str();

    // Remove any leftover '\n' or '\r'
    json_str.erase(std::remove_if(json_str.begin(), json_str.end(),
                                  [](char c){ return c == '\n' || c == '\r'; }),
                   json_str.end());

    return json_str;
}

bpt::ptree Eve::parseHeaders(istringstream& stream, string& content_type, string& content_encoding) {
    bpt::ptree headers_array;
    string line;

    while (getline(stream, line) && !line.empty() && line != "\r") {
        size_t colon_pos = line.find(':');
        if (colon_pos != string::npos) {
            string key = line.substr(0, colon_pos);
            string value = line.substr(colon_pos + 1);

            // Remove leading/trailing whitespace and any '\r' or '\n'
            boost::algorithm::trim_if(value, boost::algorithm::is_any_of(" \r\n"));

            bpt::ptree item;
            item.put("name", key);
            item.put("value", value);
            headers_array.push_back(std::make_pair("", item));

            if (key == "Content-Type") content_type = value;
            else if (key == "Content-Encoding") content_encoding = value;
        }
    }

    return headers_array;
}

bool Eve::isBase64(const string& str) {
    if (str.empty() || str.size() % 4) return false;
    size_t end = str.size();
    if (str[end-1] == '=') --end;
    if (end && str[end-1] == '=') --end;
    const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < end; ++i) if (alphabet.find(str[i]) == string::npos) return false;
    return true;
}

string Eve::base64Decode(const string& encoded_string) {
    if (!isBase64(encoded_string)) return "";
    using namespace bai;
    using It = transform_width<binary_from_base64<string::const_iterator>, 8, 6>;
    string encoded = encoded_string;
    boost::algorithm::erase_all(encoded, "\n");
    boost::algorithm::erase_all(encoded, "\r");
    size_t padding = count(encoded.begin(), encoded.end(), '=');
    replace(encoded.begin(), encoded.end(), '=', 'A');
    string decoded(It(encoded.begin()), It(encoded.end()));
    decoded.erase(decoded.end() - padding, decoded.end());
    return decoded;
}

