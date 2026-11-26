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

#ifndef ALTPROBE_IDS_JSON_H
#define ALTPROBE_IDS_JSON_H
#include "json_wire.h"
#include "detection.h"
#include "helpers.h"

inline const Json& idsChild(const Json& value, const std::string& key) {
    static const Json empty;
    auto child = value.get(key); return child ? *child : empty;
}
inline long idsNumber(const Json& value, const std::string& key) {
    const auto& child = idsChild(value, key);
    if (child.kind != 'd' && child.kind != 's') return 0;
    try { size_t used = 0; long n = std::stol(child.text, &used); return used == child.text.size() ? n : 0; }
    catch (...) { return 0; }
}
inline std::string idsField(const Json& value, const std::string& key) {
    auto s = value.string(key);
    return s == "<NA>" || s == "<N/A>" || s == "indef" || s == "-" || s == "<nil>" ? "" : s;
}
inline std::string idsIp(const std::string& value) {
    if (!isValidIp(value)) return "";
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(value, ec);
    return ec ? "" : address.to_string();
}
inline int idsPort(const Json& value, const std::string& key) {
    long n = idsNumber(value, key); return n > 0 && n <= 65535 ? static_cast<int>(n) : 0;
}
inline std::string idsEndpoint(const std::string& ip, int port) {
    std::string out = "{";
    if (!ip.empty()) out += "\"ip\":" + jsonQuote(ip) + ",";
    return out + "\"port\":" + std::to_string(port) + "}";
}
inline std::string idsEnvelope(const Event& e, int cls, int activity, const std::string& sensor) {
    const std::string cls_name = cls == 2004 ? "Detection Finding" : cls == 4001 ? "DNS Activity" :
        cls == 4002 ? "HTTP Activity" : cls == 4007 ? "TLS Activity" : "Network Activity";
    std::string agent;
    if (!e.consumer_id.empty() || !e.consumer_name.empty()) {
        agent = ",\"agent\":{\"id\":" + jsonQuote(e.consumer_id) +
            ",\"name\":" + jsonQuote(e.consumer_name) + "}";
    }
    return "{\"class_name\":" + jsonQuote(cls_name) + ",\"category_name\":" +
        jsonQuote(cls == 2004 ? "Findings" : "Network Activity") + ",\"class_uid\":" + std::to_string(cls) + ",\"category_uid\":" + (cls == 2004 ? "2" : "4") +
        ",\"activity_id\":" + std::to_string(activity) + ",\"action_id\":" + (cls == 2004 ? "2" : "1") + ",\"type_uid\":" + std::to_string(cls * 100 + activity) +
        ",\"time\":" + std::to_string(e.ts) + ",\"metadata\":{\"version\":\"1.8.0\",\"log_name\":" +
        jsonQuote(sensor + "_alertflex") + ",\"logged_time\":" + std::to_string(e.observed_ts) +
        ",\"product\":{\"name\":" + jsonQuote(sensor) + ",\"vendor_name\":" + jsonQuote(sensor) +
        "}},\"device\":{\"hostname\":" + jsonQuote(e.host_id) + "},\"src_endpoint\":" +
        idsEndpoint(e.src_ip, e.src_port) + ",\"dst_endpoint\":" + idsEndpoint(e.dst_ip, e.dst_port) + agent;
}
#endif
