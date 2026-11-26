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

#ifndef PROXY_H
#define	PROXY_H

#include "sinks.h"
#include "filter.h"
#include "config.h"
#include "source.h"
#include "http.h"
#include "classify.h"
#include "correlator.h"
#include "inventory.h"
#include "trace.h"

using namespace std;

class ProxyRecord {
public:
    
    // *** Common fields
    string host_name;  // client IP address, extructed from altprobe config or vector json field
    string request_uri; // "/alertflex-mc/user/login.xhtml"
    string gateway_origin_id; // Trusted log-source namespace; never a client header.
    string request_id; // "0e40674ded284c4b49100f4760336d53"
    string request_method; // "GET",
    string http_version; // "HTTP/1.1"
    string remote_addr; // "192.168.1.5"
    string authenticated_principal;
    string authenticated_gateway;
    string identity_name;
    string consumer_id;
    string consumer_name;
    bool agent_key_authenticated = false;
    string remote_user; // "-"
    uint64_t event_ts_ms = 0;
    size_t request_original_size = 0;
    size_t response_original_size = 0;
    bool request_truncated = false;
    bool response_truncated = false;
    bool request_missing = false;
    bool response_missing = false;
    string time_local; // "24/Oct/2025:23:09:12 +0300"
    unsigned int server_port;
    unsigned int duration; // 0.006
    unsigned int status; // 502,
    unsigned int body_bytes_sent; // 559
    string http_referer; // "http://192.168.1.20/"
    string http_host; // "192.168.1.20"
    string http_user_agent; // "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    string http_accept_language; // "en-RU,en;q=0.9,ru-RU;q=0.8,ru;q=0.7,en-GB;q=0.6,en-US;q=0.5"
    string http_accept_encoding; // "gzip, deflate, br, zstd"
    string http_connection; // "keep-alive"
    string http_cookie; // "-"
    string request_body; // "-"
    string response_body; // "-"
    string mcp_session_id; // MCP/A2A session id
    string mcp_method; // JSON-RPC method

    //  Record  HTTP
    Http http;
    
    void Reset() {
        host_name.clear();
        request_uri.clear();
        request_id.clear(); gateway_origin_id.clear();
        request_method.clear();
        http_version.clear();
        remote_addr.clear();
        remote_user.clear();
        authenticated_principal.clear(); authenticated_gateway.clear(); identity_name.clear(); consumer_id.clear(); consumer_name.clear(); agent_key_authenticated = false;
        time_local.clear();
        event_ts_ms = 0;
        request_original_size = response_original_size = 0;
        request_truncated = response_truncated = false;
        request_missing = response_missing = false;
        server_port = 0;
        duration = 0;
        status = 0;
        body_bytes_sent = 0;
        http_referer.clear();
        http_host.clear();
        http_user_agent.clear();
        http_accept_language.clear();
        http_accept_encoding.clear();
        http_connection.clear();
        http_cookie.clear();
        request_body.clear();
        response_body.clear();
        mcp_session_id.clear();
        mcp_method.clear();

        http.Reset();
    }
};

namespace bpt = boost::property_tree;

class Proxy : public Source {
public: 
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    // Keep partial lines across tail polls; bound memory independently of chunk size.
    string file_record, pending_file_record;
    bool discarding_file_record = false;
    static constexpr size_t MAX_FILE_RECORD_BYTES = 1024 * 1024;
    
    // The same HTTP analysis pipeline is used for IDS-captured HTTP. Each
    // instance belongs to one worker and writes to its own SPSC queues.
    std::string sensor_name = "proxy";
    int sensor_source = 3;
    Event ids_context;
    void ProcessIdsHttp(const Http& http, const Event& context);

    // Proxy record
    ProxyRecord ctx;
    
    Endpoint ep;
    Inventory inventory;

    bpt::ptree pt, pt1;
    stringstream ss, ss1;

    Proxy (string skey, string ekey) : Source(skey, ekey), fp(nullptr) {
        json_report.reserve(100000);
        ClearRecords();
        ResetStream();
        ferror_counter = 0;
    }
    ~Proxy() override;
    bool GetStatus() override { return source_status && (proxy_log_status || redis_status); }
    
    void ResetStream() {
        ss.str("");
        ss.clear();
        ss1.str("");
        ss1.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
        pt1.clear();
    }
    
    virtual bool Open();
    virtual void Close();
    virtual bool Go();
    
    int ReadFile();
    void IsFileModified();
    int ParsJson (int output_type);
    void CreateLogRecord ();
    Event buildEventFromProxy(const ProxyRecord& ctx);
                                        
    void ClearRecords() {
        ctx.Reset();
        ResetJsontree();
        json_report.clear();
    }
private:
    std::chrono::steady_clock::time_point redis_retry_at_{};
    bool connectRedis();
    void releaseResources(); // Called only after the worker has stopped.
};

extern boost::lockfree::spsc_queue<Http> q_modsec_proxy;
extern boost::lockfree::spsc_queue<string> q_logs_proxy;

#endif	/* PROXY_H */

