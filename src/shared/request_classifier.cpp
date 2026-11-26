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

#include "request_classifier.h"
#include "bounded_json.h"
#include <algorithm>
#include <regex>
#include <set>
#include <sstream>
#include <boost/property_tree/json_parser.hpp>

std::string RequestClassifier::endpointPathForRequest(const Http& http, RequestType type) const {
    // Keep the actual route in both counter-sync and full-log evidence.
    // Discovery templates are a separate identity, not a replacement URL.
    return normalizePath(http.url, false);
}

std::string RequestClassifier::routeTemplateForRequest(const Http& http) const {
    return normalizePath(http.url, true);
}

std::string RequestClassifier::endpointMethodForRequest(const Http& http, RequestType type) const {
    if (type == TYPE_MCP) {
        std::string method = extractJsonRpcMethod(http.request_body);
        if (method.empty())
            method = extractJsonRpcMethod(http.response_body);
        return method.empty() ? http.http_method : method;
    }

    if (type == TYPE_A2A) {
        std::string operation = extractA2aOperation(http);
        return operation.empty() ? http.http_method : operation;
    }

    return http.http_method;
}

RequestType RequestClassifier::classifyRequest(const std::string& method,
    const std::string& path,
    const std::string& headers,
    const std::string& body) {
    
    // A known A2A JSON-RPC method is stronger evidence than heuristic field counts.
    // Inspect the envelope method, not method-like text inside tool arguments.
    Json envelope;
    if (parseBoundedJson(body, envelope, 1048576, 16384) && envelope.kind == 'o' &&
            envelope.string("jsonrpc") == "2.0") {
        const std::set<std::string> a2a_methods{
            "message/send", "message/stream", "tasks/get", "tasks/cancel", "tasks/subscribe"};
        if (a2a_methods.count(envelope.string("method"))) return TYPE_A2A;
    }

    int mcp_score = 0;
    int a2a_score = 0;
    int rest_score = 0;

    // ---------------- METHOD ----------------
    if (method == "GET" || method == "POST" ||
        method == "PUT" || method == "DELETE" ||
        method == "PATCH" || method == "HEAD") {
        rest_score += 2;
    }

    if (method == "POST") mcp_score += 1;
    if (method == "POST") a2a_score += 1;

    // ---------------- PATH ----------------
    if (path.find("/api") != std::string::npos) rest_score += 3;
    
    if (path.find("/mcp") != std::string::npos) mcp_score += 5;
    if (path.find("/tools") != std::string::npos) mcp_score += 3;
    if (path.find("/invoke") != std::string::npos) mcp_score += 3;
    if (path.find("/rpc") != std::string::npos) mcp_score += 2;
    if (path.find("/.well-known/agent-card.json") != std::string::npos) a2a_score += 7;
    if (path.find("/message:send") != std::string::npos) a2a_score += 6;
    if (path.find("/message:stream") != std::string::npos) a2a_score += 6;
    if (path.find("/tasks") != std::string::npos) a2a_score += 4;
    if (path.find("/extendedAgentCard") != std::string::npos ||
        path.find("/extendedagentcard") != std::string::npos) a2a_score += 5;

    // ---------------- BODY ----------------
    if (body.find("\"jsonrpc\"") != std::string::npos) mcp_score += 5;

    if (body.find("\"method\"") != std::string::npos &&
        body.find("\"params\"") != std::string::npos) mcp_score += 4;

    // Legacy tool invocation is a top-level protocol field. An OpenAI chat
    // message with role="tool" is ordinary REST traffic, not an MCP envelope.
    // Looking for the string anywhere in the body misclassified the second
    // LLM turn and made strict policy deny a correctly approved chat endpoint.
    if (envelope.kind == 'o' && envelope.get("tool")) mcp_score += 4;

    if (body.find("\"messageId\"") != std::string::npos ||
        body.find("\"messageid\"") != std::string::npos) a2a_score += 4;
    if (body.find("\"contextId\"") != std::string::npos ||
        body.find("\"contextid\"") != std::string::npos) a2a_score += 4;
    if (body.find("\"parts\"") != std::string::npos) a2a_score += 3;
    if (body.find("\"artifacts\"") != std::string::npos) a2a_score += 4;
    if (body.find("TASK_STATE_") != std::string::npos ||
        body.find("task_state_") != std::string::npos) a2a_score += 4;
    if (body.find("message/send") != std::string::npos ||
        body.find("message/stream") != std::string::npos ||
        body.find("tasks/get") != std::string::npos) a2a_score += 5;


    // ---------------- HEADERS ----------------
    if (headers.find("application/json") != std::string::npos) {
        mcp_score += 1;
        a2a_score += 1;
        rest_score += 1;
    }

    if (headers.find("application/a2a+json") != std::string::npos) {
        a2a_score += 8;
    }

    if (headers.find("a2a-version") != std::string::npos) {
        a2a_score += 6;
    }

    if (headers.find("x-mcp") != std::string::npos) {
        mcp_score += 6;
    }

    // ---------------- DECISION ----------------
    if (a2a_score >= mcp_score + 2 && a2a_score >= rest_score + 2)
        return TYPE_A2A;

    if (mcp_score >= rest_score + 3)
        return TYPE_MCP;

    if (rest_score >= 2)
        return TYPE_REST;

    return TYPE_UNKNOWN;
}

std::string RequestClassifier::lowerCopy(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return out;
}

std::string RequestClassifier::normalizePath(const std::string& value, bool canonicalizeDynamicSegments) {
    // Match Java String.trim(): remove only surrounding code units <= U+0020.
    size_t first = 0, last = value.size();
    while (first < last && static_cast<unsigned char>(value[first]) <= 0x20) ++first;
    while (last > first && static_cast<unsigned char>(value[last - 1]) <= 0x20) --last;
    std::string path = first == last ? "/" : value.substr(first, last - first);

    size_t query = path.find('?');
    if (query != std::string::npos)
        path = path.substr(0, query);

    size_t scheme = path.find("://");
    if (scheme != std::string::npos) {
        size_t slash = path.find('/', scheme + 3);
        path = (slash != std::string::npos) ? path.substr(slash) : "/";
    }

    if (path.empty())
        path = "/";

    if (path[0] != '/')
        path = "/" + path;

    if (!canonicalizeDynamicSegments) return path;
    std::string normalized;
    size_t begin = 0;
    while (true) {
        size_t end = path.find('/', begin);
        normalized += normalizeSegment(path.substr(begin, end == std::string::npos ? end : end - begin));
        if (end == std::string::npos) break;
        normalized += '/'; begin = end + 1;
    }
    return normalized;
}

std::string RequestClassifier::normalizeSegment(const std::string& segment) {
    static const std::regex uuid("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    static const std::regex number("^\\d+$");
    static const std::regex hex("^[0-9a-fA-F]{16,}$");
    static const std::regex hash("^[a-f0-9]{32,}$");
    static const std::regex token("^[A-Za-z0-9+/=_-]{24,}$");

    if (std::regex_match(segment, number))
        return "{id}";
    if (std::regex_match(segment, uuid))
        return "{uuid}";
    if (std::regex_match(segment, hex) || std::regex_match(segment, hash))
        return "{hash}";
    const bool has_digit = std::any_of(segment.begin(), segment.end(), [](unsigned char c) {
        return c >= '0' && c <= '9';
    });
    if (std::regex_match(segment, token) && has_digit)
        return "{token}";

    return segment;
}

bool RequestClassifier::sameEndpointPath(const std::string& left, const std::string& right) {
    return normalizePath(left, false) == normalizePath(right, false);
}

bool RequestClassifier::parseJson(const std::string& text, boost::property_tree::ptree& out) {
    if (text.empty() || text == "null" || text == "{}")
        return false;

    try {
        std::stringstream ss(text);
        boost::property_tree::read_json(ss, out);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string RequestClassifier::getJsonString(
    const boost::property_tree::ptree& pt,
    const std::vector<std::string>& paths)
{
    for (const auto& path : paths) {
        auto value = pt.get_optional<std::string>(path);
        if (value && !value.get().empty())
            return value.get();
    }
    return "";
}

std::string RequestClassifier::extractJsonRpcMethod(const std::string& text) {
    boost::property_tree::ptree pt;
    if (!parseJson(text, pt))
        return "";

    return getJsonString(pt, {"method"});
}

std::string RequestClassifier::extractA2aOperation(const Http& http) {
    std::string method = lowerCopy(extractJsonRpcMethod(http.request_body));
    if (method.empty())
        method = lowerCopy(extractJsonRpcMethod(http.response_body));

    if (method == "message/send")
        return "message_send";
    if (method == "message/stream")
        return "message_stream";
    if (method == "tasks/get")
        return "task_access";
    if (method == "tasks/cancel")
        return "task_cancel";
    if (method == "tasks/subscribe")
        return "task_subscribe";

    std::string joined = lowerCopy(
        http.url + " " +
        http.request_headers + " " +
        http.request_body + " " +
        http.response_body
    );

    if (joined.find("/.well-known/agent-card.json") != std::string::npos)
        return "agent_card";
    if (joined.find("/extendedagentcard") != std::string::npos)
        return "extended_agent_card";
    if (joined.find("/message:stream") != std::string::npos)
        return "message_stream";
    if (joined.find("/message:send") != std::string::npos)
        return "message_send";
    if (joined.find(":cancel") != std::string::npos)
        return "task_cancel";
    if (joined.find(":subscribe") != std::string::npos)
        return "task_subscribe";
    if (joined.find("/tasks") != std::string::npos ||
        joined.find("\"taskid\"") != std::string::npos ||
        joined.find("\"task_id\"") != std::string::npos)
        return "task_access";
    if (joined.find("application/a2a+json") != std::string::npos ||
        joined.find("a2a-version") != std::string::npos ||
        joined.find("\"protocol\":\"a2a\"") != std::string::npos)
        return "a2a_http";

    return "";
}

