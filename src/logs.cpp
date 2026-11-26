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

#include "helpers.h"
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include "http_io.h"
#include "tls_client.h"
#include "logs.h"
#include "bounded_json.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <utility>
#include <unistd.h>
#include <sstream>
#include <boost/lockfree/spsc_queue.hpp>

// gzip
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/copy.hpp>

// http (as in Filter)
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

// internal
#include "base64.h"
#include "proxy.h"
#include "suricata.h"
#include "filter.h"


using tcp = boost::asio::ip::tcp;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;

static std::string trimCopy(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && std::isspace((unsigned char)value[start]))
        start++;

    size_t end = value.size();
    while (end > start && std::isspace((unsigned char)value[end - 1]))
        end--;

    return value.substr(start, end - start);
}

static std::string upperCopy(const std::string& value) {
    std::string out = trimCopy(value);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return (char)std::toupper(c);
    });
    return out;
}

static void normalizeCounterEvent(ApiCounterEvent& counter) {
    counter.path = trimCopy(counter.path);
    counter.method = trimCopy(counter.method);

    std::string type = upperCopy(counter.type);
    if (type != "MCP" && type != "A2A")
        type = "REST";
    counter.type = type;

    if (counter.type == "REST")
        counter.method = upperCopy(counter.method);
}

// ---------------- MAIN LOOP ----------------

bool Logs::Go() {
    
    size_t pending_bytes = 0;
    for (const auto& record : logs_list) pending_bytes += record.id.size() + record.event.size();
    size_t dropped = 0;
    auto drain = [&](auto& queue) {
        // Snapshot the available count: a busy producer must not prevent delivery.
        const size_t available = queue.read_available();
        for (size_t i = 0; i < available && queue.pop(rec); ++i) {
            const size_t bytes = rec.size() + 36; // UUID retained with each record.
            if (logs_list.size() >= MAX_PENDING_LOGS || rec.size() > MAX_PENDING_LOG_RECORD_BYTES ||
                    bytes > MAX_PENDING_LOG_BYTES - pending_bytes) {
                ++dropped;
                continue;
            }
            logs_list.push_back({boost::uuids::to_string(boost::uuids::random_generator()()), std::move(rec)});
            pending_bytes += bytes;
        }
    };
    drain(q_logs_proxy);
    drain(q_logs_suricata);
    // Release the scratch string, including an oversized rejected record.
    std::string{}.swap(rec);
    if (dropped) SysLog((char*)("[Logs] pending discovery limit reached; new records dropped=" +
            std::to_string(dropped)).c_str());

    ProcessLogs();
    ProcessCounters();

    sleep(5);

    return source_status;
}

// ---------------- PROCESS ----------------

void Logs::ProcessLogs() {
    if (logs_list.empty()) return;
    std::vector<PendingLog> retained;
    size_t offset = 0;
    while (offset < logs_list.size()) {
        std::string batch = "{\"delivery_version\":1,\"logs\":[";
        std::vector<PendingLog> submitted;
        while (offset + submitted.size() < logs_list.size()) {
            const auto& record = logs_list[offset + submitted.size()];
            // Quote event JSON as a string: even malformed source records can
            // receive an individual rejection without poisoning a whole batch.
            const auto entry = "{\"id\":\"" + record.id + "\",\"event\":\"" +
                    escapeJsonString(record.event) + "\"}";
            if (!submitted.empty() && batch.size() + entry.size() > MAX_BATCH_SIZE) break;
            if (!submitted.empty()) batch += ',';
            batch += entry;
            submitted.push_back(record);
        }
        batch += "]}";
        std::string response;
        std::vector<std::string> statuses;
        if (!sendCompressedBatch(batch, &response) || !parseLogAcknowledgement(response, submitted, statuses)) {
            retained.insert(retained.end(), logs_list.begin() + offset, logs_list.end());
            SysLog((char*)"[Logs] batch not acknowledged; stable record IDs retained for retry");
            break;
        }
        for (size_t i = 0; i < submitted.size(); ++i) {
            if (statuses[i] == "retry" || (statuses[i] == "rejected" && !quarantineRecord(submitted[i])))
                retained.push_back(std::move(submitted[i]));
        }
        offset += submitted.size();
    }
    logs_list.swap(retained);
}

// Retain permanently rejected evidence in a private, atomic file. A record is
// removed from memory only after directory fsync; disk failure preserves retries.
bool Logs::quarantineRecord(const PendingLog& record) {
    int directory = -1, fd = -1;
    std::string temp;
    bool published = false;
    try {
        const bool created = std::filesystem::create_directories(logs_rejected_dir);
        if (created && ::chmod(logs_rejected_dir.c_str(), 0700)) throw std::runtime_error("cannot protect quarantine");
        directory = ::open(logs_rejected_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat state{};
        if (directory < 0 || fstat(directory, &state) || state.st_uid != geteuid() || (state.st_mode & 0077))
            throw std::runtime_error("unsafe quarantine directory");
        const auto content = "{\"id\":\"" + record.id + "\",\"event\":\"" + escapeJsonString(record.event) + "\"}";
        const auto file = record.id + ".json";
        // If fsync failed after a prior publication, verify the existing file
        // before treating it as a durable quarantine record on a later attempt.
        fd = openat(directory, file.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            if (fstat(fd, &state) || !S_ISREG(state.st_mode) || state.st_uid != geteuid() ||
                    (state.st_mode & 0077) || state.st_size != static_cast<off_t>(content.size()))
                throw std::runtime_error("unsafe existing quarantine record");
            std::string existing(content.size(), '\0');
            size_t offset = 0;
            while (offset < existing.size()) {
                ssize_t count = read(fd, &existing[offset], existing.size() - offset);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) throw std::runtime_error("cannot verify quarantine record");
                offset += count;
            }
            if (existing != content) throw std::runtime_error("quarantine ID conflict");
            published = fsync(directory) == 0;
        } else {
            if (errno != ENOENT) throw std::runtime_error("cannot read quarantine record");
            temp = record.id + "." + boost::uuids::to_string(boost::uuids::random_generator()()) + ".tmp";
            fd = openat(directory, temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) throw std::runtime_error("cannot stage quarantine record");
            size_t offset = 0;
            while (offset < content.size()) {
                ssize_t count = write(fd, content.data() + offset, content.size() - offset);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) throw std::runtime_error("cannot write quarantine record");
                offset += count;
            }
            if (fsync(fd)) throw std::runtime_error("cannot sync quarantine record");
            if (linkat(directory, temp.c_str(), directory, file.c_str(), 0))
                throw std::runtime_error("cannot publish quarantine record");
            unlinkat(directory, temp.c_str(), 0);
            temp.clear();
            published = fsync(directory) == 0;
        }
    } catch (const std::exception& error) {
        SysLog((char*)("[Logs] quarantine failed; record retained: " + std::string(error.what())).c_str());
    }
    if (fd >= 0) ::close(fd);
    if (directory >= 0) {
        if (!temp.empty()) unlinkat(directory, temp.c_str(), 0);
        ::close(directory);
    }
    if (published) SysLog((char*)("[Logs] rejected record=" + record.id + " retained for operator review").c_str());
    return published;
}

// ---------------- PROCESS API COUNTERS ----------------

void Logs::ProcessCounters() {
    ApiCounterEvent event;
    auto drainCounters = [&](auto& input) {
    const auto available = input.read_available();
    for (size_t i=0; i<available && input.pop(event); ++i) {
        normalizeCounterEvent(event);
        if (event.path.size()>255 || event.method.size()>128 || event.gateway_origin_id.empty() ||
                event.gateway_origin_id.size()>255 || event.observation_id.empty() || event.observation_id.size()>255) {
            SysLog((char*)"[Logs] Invalid discovery observation; not counted"); continue;
        }
        const auto key=event.type+"\n"+event.method+"\n"+event.path+"\n"+event.gateway_origin_id+"\n"+event.observation_id;
        if (counters_list.size()>=MAX_COUNTER_KEYS && !counters_list.count(key)) {
            SysLog((char*)"[Logs] Discovery pending limit reached; new observation dropped"); continue;
        }
        counters_list.emplace(key,std::move(event));
    }
    };
    drainCounters(q_api_counters_proxy);
    drainCounters(q_api_counters_suricata);
    while (!counters_list.empty()) {
        std::vector<ApiCounterEvent> batch;
        std::vector<std::string> keys;
        for (const auto& item:counters_list) {
            if (batch.size()>=128) break;
            keys.push_back(item.first); batch.push_back(item.second);
        }
        if (!sendCountersToAF(batch)) return;
        for (const auto& key:keys) counters_list.erase(key);
    }
}

// ---------------- COMPRESS ----------------

bool Logs::sendCompressedBatch(const std::string& json, std::string* response) {
    
    if (log_debug) {
        SysLog((char*)"Log to Alertflex:");
        SysLog((char*)json.c_str());
    }

    std::stringstream input;
    input << json;

    boost::iostreams::filtering_streambuf<boost::iostreams::input> in;
    in.push(boost::iostreams::gzip_compressor());
    in.push(input);

    std::stringstream compressed_stream;
    boost::iostreams::copy(in, compressed_stream);
    boost::iostreams::close(in);

    std::string compressed = compressed_stream.str();

    if (compressed.empty())
        return false;

    return sendBatchToAF(compressed, response) == 1;
}

// ---------------- SEND ----------------

int Logs::sendBatchToAF(const std::string& compressed, std::string* response) {

    if (!af_enable) return 1;

    if (af_url.empty() || af_key.empty()) {
        SysLog((char*)"[Logs] Alertflex not configured");
        return 0;
    }

    try {
        bool is_https = (af_url.find("https://") == 0);
        bool is_http = (af_url.find("http://") == 0);
        if (!is_https && !is_http) {
            SysLog((char*)"[Logs] Alertflex URL must start with http:// or https://");
            return 0;
        }

        std::string url = af_url.substr(is_https ? 8 : 7);

        // -------- HOST + BASE PATH --------
        size_t slash = url.find('/');
        std::string host_part = (slash != std::string::npos) ? url.substr(0, slash) : url;
        std::string base_path = (slash != std::string::npos) ? url.substr(slash) : "";

        // -------- NORMALIZE PATH --------
        if (!base_path.empty() && base_path.back() == '/') {
            base_path.pop_back();
        }
        
        // -------- FINAL TARGET --------
        std::string target = base_path + "/logs";

        // -------- HOST / PORT --------
        std::string host, port;

        size_t colon = host_part.find(':');
        if (colon != std::string::npos) {
            host = host_part.substr(0, colon);
            port = host_part.substr(colon + 1);
        } else {
            host = host_part;
            port = is_https ? "443" : "80";
        }

        // -------- BASE64 --------
        std::string encoded;
        if (!Base64::Encode(compressed, &encoded)) {
            SysLog((char*)"[Logs] Base64 encode failed");
            return 0;
        }

        // -------- JSON --------
        std::string json =
            "{"
            "\"text_type\":\"HTTP_GZIP\","
            "\"encoding\":\"base64\","
            "\"asset\":\"" + escapeJsonString(asset_name) + "\","
            "\"host\":\"" + escapeJsonString(host_name) + "\","
            "\"text_sample\":\"" + encoded + "\""
            "}";

        std::string auth = "Bearer " + af_key;

        return sendHttpRequest(
            is_https,
            host,
            port,
            target,
            "POST",
            json,
            auth,
            {},
            "application/json", response
        ) ? 1 : 0;

    } catch (std::exception const& e) {
        SysLog((char*)e.what());
        return 0;
    }
}

// ---------------- SEND API COUNTERS ----------------

std::string Logs::jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (char c : value) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"': out.append("\\\""); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

bool Logs::sendCountersToAF(const std::vector<ApiCounterEvent>& counters) {

    if (!af_enable) return true;

    if (af_url.empty() || af_key.empty()) {
        SysLog((char*)"[Logs] Alertflex not configured for API counter sync");
        return false;
    }

    try {
        bool is_https = (af_url.find("https://") == 0);
        bool is_http = (af_url.find("http://") == 0);
        if (!is_https && !is_http) {
            SysLog((char*)"[Logs] Alertflex URL must start with http:// or https://");
            return false;
        }

        std::string url = af_url.substr(is_https ? 8 : 7);

        size_t slash = url.find('/');
        std::string host_part = (slash != std::string::npos) ? url.substr(0, slash) : url;
        std::string base_path = (slash != std::string::npos) ? url.substr(slash) : "";

        if (!base_path.empty() && base_path.back() == '/') {
            base_path.pop_back();
        }

        std::string target = base_path + "/inventory/" + asset_name + "/counters";

        std::string host, port;
        size_t colon = host_part.find(':');
        if (colon != std::string::npos) {
            host = host_part.substr(0, colon);
            port = host_part.substr(colon + 1);
        } else {
            host = host_part;
            port = is_https ? "443" : "80";
        }

        std::stringstream body;
        body << "{\"discovery_version\":2,\"counters\":[";
        bool first=true;
        for (const auto& c:counters) {
            if (!first) body << ",";
            first=false;
            body << "{\"path\":\"" << jsonEscape(c.path) << "\",\"method\":\"" << jsonEscape(c.method)
                 << "\",\"type\":\"" << jsonEscape(c.type) << "\",\"gatewayOriginId\":\"" << jsonEscape(c.gateway_origin_id)
                 << "\",\"observationId\":\"" << jsonEscape(c.observation_id) << "\",\"lastObservedMs\":" << c.last_observed_ms << "}";
        }
        body << "]}";
        std::string ack;
        if (!sendHttpRequest(is_https,host,port,target,"POST",body.str(),"Bearer "+af_key,{},"application/json",&ack)) return false;
        Json parsed;
        if (!parseBoundedJson(ack,parsed) || !parsed.get("discovery_version") || parsed.get("discovery_version")->text!="2" ||
                !parsed.get("received") || parsed.get("received")->text!=std::to_string(counters.size())) {
            SysLog((char*)"[Logs] Invalid discovery v2 ACK; observations retained"); return false;
        }
        return true;

    } catch (std::exception const& e) {
        std::string err = "[Logs] API counter sync exception: " + std::string(e.what());
        SysLog((char*)err.c_str());
        return false;
    }
}

// ---------------- HTTP CLIENT ----------------

bool Logs::sendHttpRequest(
    bool is_https,
    const std::string& host,
    const std::string& port,
    const std::string& target,
    const std::string& method,
    const std::string& body,
    const std::string& auth,
    const std::map<std::string, std::string>& headers,
    const std::string& content_type,
    std::string* response
) {
    try {
        const auto result = bounded_http::request(is_https, host, port, target,
            method, body, auth, headers, body.empty() ? "" : content_type,
            std::chrono::seconds(60), [&] { return !source_status.load(); },
            1024 * 1024, af_tls_verify, af_tls_ca_file);
        if (response) *response = result.body();
        return result.result() == http::status::ok || result.result() == http::status::created ||
                result.result() == http::status::no_content;
    } catch (const std::exception& error) {
        SysLog((char*)("[Logs] HTTP exception: " + std::string(error.what())).c_str());
        return false;
    }
}
