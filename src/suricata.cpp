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

#include "suricata.h"
#include "ids_json.h"
#include "correlator.h"
#include "classify.h"
#include "api_guard.h"
#include "eve.h"
#include "llm_guard.h"
#include <set>
#include <initializer_list>

boost::lockfree::spsc_queue<Http> q_modsec_suricata{1024};
boost::lockfree::spsc_queue<std::string> q_logs_suricata{1024};
boost::lockfree::spsc_queue<ApiCounterEvent> q_api_counters_suricata{1024};
#include "suricata_signals.inc"

namespace {
std::string domainName(std::string value) {
    value = lowerCopy(value);
    if (!value.empty() && value.back() == '.') value.pop_back();
    return value;
}
std::string decodedBody(const Json& http, const std::string& key) {
    std::string value = http.string(key);
    if (value.empty() || !Eve::isBase64(value)) return "";
    try { return Eve::base64Decode(value); } catch (...) { return ""; }
}
}

bool parseSuricataRecord(const std::string& line, const std::string& default_host,
    SuricataObservation& out, const std::string& default_consumer_id,
    const std::string& default_consumer_name) {
    out = SuricataObservation{}; out.http.Reset(); Json doc;
    if (!parseBoundedJson(line, doc, 262144, 8192) || doc.kind != 'o') return false;
    Event& e = out.event;
    const std::string type = doc.string("event_type");
    const Json& tls = idsChild(doc, "tls");
    const Json& dns = idsChild(doc, "dns");
    const Json& http = idsChild(doc, "http");
    const Json& alert = idsChild(doc, "alert");
    const Json& agent = idsChild(doc, "agent");
    e.ts = parseTimeToMillis(doc.string("timestamp")); e.observed_ts = eventTimeMillis(0);
    e.source = 2; e.host_id = idsField(doc, "host_name");
    if (e.host_id.empty()) e.host_id = default_host;
    e.consumer_id = idsField(agent, "id");
    if (e.consumer_id.empty()) e.consumer_id = idsField(doc, "consumer_id");
    if (e.consumer_id.empty()) e.consumer_id = default_consumer_id;
    e.consumer_name = idsField(agent, "name");
    if (e.consumer_name.empty()) e.consumer_name = idsField(doc, "consumer_name");
    if (e.consumer_name.empty()) e.consumer_name = default_consumer_name;
    e.src_ip = idsIp(doc.string("src_ip")); e.dst_ip = idsIp(doc.string("dest_ip"));
    e.src_port = idsPort(doc, "src_port"); e.dst_port = idsPort(doc, "dest_port");
    e.protocol = lowerCopy(doc.string("proto"));
    e.flow_id = idsChild(doc, "flow_id").text;
    e.rule = alert.string("signature");
    if (!e.flow_id.empty() && doc.get("tx_id")) e.operation_id = e.flow_id + ":" + idsChild(doc, "tx_id").text;
    e.sni = domainName(tls.string("sni")); e.ja3 = idsChild(tls, "ja3").string("hash");
    // EVE TLS records describe client/server tuples; response alerts and
    // unidirectional netflows use packet direction and must be reversed.
    if (((type == "alert" && dns.kind != 'o') || type == "netflow") && doc.string("direction") == "to_client") {
        std::swap(e.src_ip, e.dst_ip); std::swap(e.src_port, e.dst_port);
    }
    if (!e.sni.empty() && (type == "tls" || type == "alert")) {
        Event n = e; n.signal = SIG_TLS_SNI_LLM; n.network_evidence = "tls_sni";
        out.network.push_back(std::move(n));
    }
    if (type == "tls") {
        out.class_uid = 4007;
        out.ocsf = idsEnvelope(e, 4007, 1, "suricata") + ",\"severity_id\":1,\"tls\":{\"sni\":" +
            jsonQuote(e.sni) + ",\"subject\":" + jsonQuote(tls.string("subject")) + ",\"issuer\":" +
            jsonQuote(tls.string("issuerdn")) + ",\"version\":" + jsonQuote(tls.string("version")) +
            ",\"ja3_hash\":" + jsonQuote(e.ja3) + "}}";
    } else if (type == "dns" || (type == "alert" && dns.kind == 'o')) {
        std::string query = dns.string("rrname"), rrtype = dns.string("rrtype");
        if (query.empty()) query = idsChild(dns, "query").string("rrname");
        const Json& queries = idsChild(dns, "queries");
        if (query.empty() && queries.kind == 'a' && !queries.children.empty()) {
            query = queries.children.front().second.string("rrname");
            rrtype = queries.children.front().second.string("rrtype");
        }
        query = domainName(query);
        const auto dns_type = dns.string("type");
        bool answer = dns_type == "answer" || dns_type == "response";
        if (answer) { // resolver -> client is not client -> provider
            std::swap(e.src_ip, e.dst_ip); std::swap(e.src_port, e.dst_port);
        }
        const Json& answers = idsChild(dns, "answers");
        if (answer && dns.string("rcode") == "NOERROR" && !query.empty()) {
            std::set<std::string> names{query};
            // Only accept A/AAAA on the queried name or its CNAME chain.
            for (size_t i = 0; i < answers.children.size(); ++i) {
                for (const auto& item : answers.children) {
                    const auto& a = item.second;
                    if (a.string("rrtype") == "CNAME" && names.count(domainName(a.string("rrname"))))
                        names.insert(domainName(a.string("rdata")));
                }
            }
            auto addAnswer = [&](const std::string& ip) {
                if (idsIp(ip).empty()) return;
                Event n = e; n.dst_ip = idsIp(ip); n.dst_port = 0; n.src_port = 0;
                n.protocol.clear(); n.sni = query; n.network_evidence = "dns_answer"; n.signal = SIG_DNS_LLM;
                out.network.push_back(std::move(n));
            };
            for (const auto& item : answers.children) {
                const auto& a = item.second;
                if ((a.string("rrtype") == "A" || a.string("rrtype") == "AAAA") &&
                    names.count(domainName(a.string("rrname")))) addAnswer(a.string("rdata"));
            }
            // Grouped EVE DNS responses have no per-answer owner names.
            if (answers.children.empty()) {
                const auto& grouped = idsChild(dns, "grouped");
                for (const char* kind : {"A", "AAAA"})
                    for (const auto& item : idsChild(grouped, kind).children) addAnswer(item.second.text);
            }
        }
        out.class_uid = 4001;
        out.ocsf = idsEnvelope(e, 4001, 1, "suricata") + ",\"severity_id\":1,\"dns_query\":{\"hostname\":" +
            jsonQuote(query) + ",\"type\":" + jsonQuote(dns_type) + ",\"rrtype\":" + jsonQuote(rrtype) +
            ",\"rcode\":" + jsonQuote(dns.string("rcode")) + ",\"query_id\":" + std::to_string(idsNumber(dns, "id")) + "}";
        if (answers.kind == 'a') out.ocsf += ",\"dns_answers\":" + wireJson(answers);
        out.ocsf += "}";
    } else if (type == "flow" || type == "netflow") {
        const auto& f = idsChild(doc, type);
        long bytes = type == "flow" ? idsNumber(f, "bytes_toserver") + idsNumber(f, "bytes_toclient") : idsNumber(f, "bytes");
        long packets = type == "flow" ? idsNumber(f, "pkts_toserver") + idsNumber(f, "pkts_toclient") : idsNumber(f, "pkts");
        out.class_uid = 4005;
        out.ocsf = idsEnvelope(e, 4005, 1, "suricata") + ",\"severity_id\":1,\"connection_info\":{\"bytes\":" +
            std::to_string(std::max(0L, bytes)) + ",\"packets\":" + std::to_string(std::max(0L, packets)) +
            ",\"protocol_name\":" + jsonQuote(e.protocol) + "},\"start_time\":" +
            std::to_string(parseTimeToMillis(f.string("start"))) + ",\"end_time\":" +
            std::to_string(parseTimeToMillis(f.string("end"))) + "}";
    } else if (type != "http" && type != "alert") return false;

    if ((type == "http" || type == "alert") && http.kind == 'o') {
        e.http_method = http.string("http_method"); e.url = http.string("url");
        e.user_agent = http.string("http_user_agent"); e.status = idsNumber(http, "status");
        if (!http.string("hostname").empty()) {
            Event n = e; n.sni = domainName(http.string("hostname"));
            n.network_evidence = "http_host"; n.signal = SIG_AI_PROVIDER_USAGE;
            out.network.push_back(std::move(n));
        }
        out.class_uid = 4002;
        int activity = e.http_method == "CONNECT" ? 1 : e.http_method == "DELETE" ? 2 : e.http_method == "GET" ? 3 :
            e.http_method == "HEAD" ? 4 : e.http_method == "OPTIONS" ? 5 : e.http_method == "POST" ? 6 :
            e.http_method == "PUT" ? 7 : e.http_method == "TRACE" ? 8 : 99;
        out.ocsf = idsEnvelope(e, 4002, activity, "suricata") + ",\"severity_id\":1,\"http_request\":{\"http_method\":" +
            jsonQuote(e.http_method) + ",\"url\":" + jsonQuote(e.url) + ",\"user_agent\":" + jsonQuote(e.user_agent) +
            "},\"http_response\":{\"code\":" + std::to_string(e.status) + "}}";
        // HTTP content inspection is retained as an IDS-alert fallback only.
        // Ordinary EVE HTTP activity never replaces gateway inventory/tracing.
        out.inspect_http = type == "alert";
        if (e.sni.empty()) e.sni = domainName(http.string("hostname"));
        if (out.inspect_http) {
            e.network_evidence = "ids_http";
            e.request_body = decodedBody(http, "http_request_body");
            e.response_body = decodedBody(http, "http_response_body");
            e.request_missing = e.request_body.empty(); e.response_missing = e.response_body.empty();
            Eve parser;
            std::string payload = doc.string("payload");
            std::string header_text = "Host: " + http.string("hostname") + "\r\n";
            if (Eve::isBase64(payload)) {
                auto decoded = Eve::base64Decode(payload);
                if (!e.http_method.empty() && decoded.rfind(e.http_method + " ", 0) == 0) header_text = decoded;
            }
            std::string headers = parser.getHeaders(header_text, e.http_method, e.url, http.string("protocol"));
            e.signal = classifyHttpMcpSignal(e.http_method, e.url, headers, e.request_body, e.response_body, &e.guard);
            SignalType ids_signal = suricataSidSignal(idsNumber(alert, "signature_id"));
            if (ids_signal == SIG_UNKNOWN) ids_signal = mapSuricataTextToSignal(e.rule, alert.string("category"));
            if (ids_signal != SIG_UNKNOWN && e.guard.kind != "threat") {
                if (e.signal != ids_signal) e.guard = GuardMatch{};
                e.signal = ids_signal;
            }
            auto& h = out.http;
            h.event_ts_ms = e.ts; h.identity_host = e.host_id; h.client_ip = e.src_ip; h.server_ip = e.dst_ip;
            h.server_port = e.dst_port; h.http_method = e.http_method; h.url = e.url; h.status = e.status;
            h.version = http.string("protocol"); h.request_headers = headers;
            h.request_body = e.request_body; h.response_body = e.response_body;
            h.request_missing = e.request_missing; h.response_missing = e.response_missing;
            h.request_original_size = e.request_body.size(); h.response_original_size = e.response_body.size();
        }
    }
    if (type == "alert" && out.ocsf.empty()) {
        out.class_uid = 2004;
        long priority = idsNumber(alert, "severity");
        out.ocsf = idsEnvelope(e, 2004, 1, "suricata") + ",\"severity_id\":" +
            std::to_string(priority == 1 ? 4 : priority == 2 ? 3 : priority == 3 ? 2 : 1) +
            ",\"finding_info\":{\"title\":" + jsonQuote(e.rule) + ",\"uid\":" +
            jsonQuote(idsChild(alert, "signature_id").text) + "}}";
    }
    return out.class_uid != 0;
}

bool Suricata::processLine(const std::string& line) {
    SuricataObservation o;
    if (!parseSuricataRecord(line, host_name, o, consumerId(), consumerName())) return false;
    if (o.inspect_http && !isInternalCollectorDest(o.http.url, o.http.server_ip, o.http.server_port)) {
        if (LogProcessingEnabled()) http_pipeline.ProcessIdsHttp(o.http, o.event);
    }
    if (LogProcessingEnabled() && !o.inspect_http) sk.sendOcsfToLogSinks(o.ocsf, o.class_uid, "indef", "suricata");
    return true;
}
