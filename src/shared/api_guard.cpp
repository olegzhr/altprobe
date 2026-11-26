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

#include "api_guard.h"
#include "diagnostic.h"
#include "bounded_json.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <yaml-cpp/yaml.h>

ApiGuard apiGuard;

namespace {
constexpr size_t GUARD_MAX_INPUT = 262144;
constexpr size_t MAX_CONFIG = 262144;
constexpr size_t MAX_NODES = 4096;
constexpr size_t MAX_DEPTH = 32;
constexpr size_t MAX_FIELDS = 512;

void utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out += static_cast<char>(cp);
    else if (cp < 0x800) {
        out += static_cast<char>(0xc0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 63));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xe0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 63));
        out += static_cast<char>(0x80 | (cp & 63));
    } else {
        out += static_cast<char>(0xf0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 63));
        out += static_cast<char>(0x80 | ((cp >> 6) & 63));
        out += static_cast<char>(0x80 | (cp & 63));
    }
}

// Deliberately bounded normalization: Latin/Cyrillic case folding, fullwidth
// ASCII, Unicode whitespace, zero-width format marks. Not full Unicode NFKC.
std::string normalize(const std::string& input, bool& valid) {
    std::string out;
    for (size_t i = 0; i < input.size(); ) {
        unsigned char c = input[i++];
        uint32_t cp = c;
        if (c >= 0x80) {
            size_t extra = c >= 0xc2 && c <= 0xdf ? 1 :
                c >= 0xe0 && c <= 0xef ? 2 : c >= 0xf0 && c <= 0xf4 ? 3 : 0;
            if (!extra || i + extra > input.size()) { valid = false; out += ' '; continue; }
            cp = c & (extra == 1 ? 31 : extra == 2 ? 15 : 7);
            bool ok = true;
            for (size_t j = 0; j < extra; ++j) {
                unsigned char d = input[i + j];
                if ((d & 0xc0) != 0x80) { ok = false; break; }
                cp = (cp << 6) | (d & 63);
            }
            if (!ok) { valid = false; out += ' '; continue; }
            i += extra;
            if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
                (extra == 3 && cp < 0x10000) || cp > 0x10ffff ||
                (cp >= 0xd800 && cp <= 0xdfff)) { valid = false; out += ' '; continue; }
        }
        if (cp == 0x200b || cp == 0x200c || cp == 0x200d || cp == 0x2060 ||
            cp == 0xfeff || cp == 0xad || (cp >= 0x202a && cp <= 0x202e) ||
            (cp >= 0x2066 && cp <= 0x2069)) continue;
        if (cp >= 0xff01 && cp <= 0xff5e) cp -= 0xfee0;
        if (cp >= 'A' && cp <= 'Z') cp += 32;
        if ((cp >= 0xc0 && cp <= 0xd6) || (cp >= 0xd8 && cp <= 0xde)) cp += 32;
        if ((cp >= 0x100 && cp <= 0x12f && cp % 2 == 0) ||
            (cp >= 0x132 && cp <= 0x137 && cp % 2 == 0) ||
            (cp >= 0x139 && cp <= 0x148 && cp % 2 == 1) ||
            (cp >= 0x14a && cp <= 0x177 && cp % 2 == 0) ||
            (cp >= 0x179 && cp <= 0x17e && cp % 2 == 1) ||
            (cp >= 0x1e00 && cp <= 0x1e95 && cp % 2 == 0) ||
            (cp >= 0x1ea0 && cp <= 0x1ef9 && cp % 2 == 0)) ++cp;
        if (cp == 0x130) cp = 'i'; // Dotted Latin I; locale-independent detection folding.
        if (cp == 0x178) cp = 0xff;
        if (cp == 0x1e9e) cp = 0xdf;
        if (cp >= 0x410 && cp <= 0x42f) cp += 32;
        if (cp == 0x401) cp = 0x451;
        if (cp <= 32 || cp == 0x7f || cp == 0xa0 || cp == 0x1680 ||
            (cp >= 0x2000 && cp <= 0x200a) || cp == 0x2028 || cp == 0x2029 ||
            cp == 0x202f || cp == 0x205f || cp == 0x3000) {
            if (!out.empty() && out.back() != ' ') out += ' ';
        } else utf8(out, cp);
    }
    if (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

std::string norm(const std::string& s) {
    bool valid = true;
    return normalize(s, valid);
}

// Inputs here are normalized valid UTF-8. Code point boundaries distinguish
// Unicode punctuation from letters; byte-level c >= 0x80 cannot do this.
uint32_t pointAt(const std::string& text, size_t pos) {
    if (pos >= text.size()) return 0;
    unsigned char c = text[pos++];
    if (c < 0x80) return c;
    size_t extra = c < 0xe0 ? 1 : c < 0xf0 ? 2 : 3;
    uint32_t cp = c & (extra == 1 ? 31 : extra == 2 ? 15 : 7);
    for (size_t i = 0; i < extra && pos < text.size(); ++i)
        cp = (cp << 6) | (static_cast<unsigned char>(text[pos++]) & 63);
    return cp;
}

uint32_t pointBefore(const std::string& text, size_t pos) {
    if (!pos) return 0;
    --pos;
    while (pos && (static_cast<unsigned char>(text[pos]) & 0xc0) == 0x80) --pos;
    return pointAt(text, pos);
}

bool phraseScript(uint32_t cp) {
    // Phrase matching in scripts where spaces do not reliably delimit words.
    return (cp >= 0x3400 && cp <= 0x9fff) || (cp >= 0xf900 && cp <= 0xfaff) ||
        (cp >= 0x20000 && cp <= 0x3134f) || (cp >= 0x3040 && cp <= 0x30ff) ||
        (cp >= 0x31f0 && cp <= 0x31ff) || (cp >= 0xac00 && cp <= 0xd7a3);
}

bool wordPoint(uint32_t cp) {
    if (cp < 128) return std::isalnum(static_cast<unsigned char>(cp)) || cp == '_';
    if (phraseScript(cp)) return false; // Also permits Latin terms next to CJK text.
    return (cp >= 0xc0 && cp <= 0x2af && cp != 0xd7 && cp != 0xf7) ||
        (cp >= 0x300 && cp <= 0x52f) || (cp >= 0x1e00 && cp <= 0x1eff) ||
        (cp >= 0x620 && cp <= 0x65f) || (cp >= 0x660 && cp <= 0x669) ||
        (cp >= 0x66e && cp <= 0x6d3) || (cp >= 0x6d5 && cp <= 0x6ed) ||
        (cp >= 0x6f0 && cp <= 0x6ff) || (cp >= 0x900 && cp <= 0x97f && cp != 0x964 && cp != 0x965);
}

bool termAt(const std::string& text, const std::string& term, size_t pos) {
    if (text.compare(pos, term.size(), term) != 0) return false;
    if (wordPoint(pointAt(term, 0)) && pos && wordPoint(pointBefore(text, pos))) return false;
    size_t end = pos + term.size();
    return !(wordPoint(pointBefore(term, term.size())) && end < text.size() && wordPoint(pointAt(text, end)));
}

// Typed, strict JSON parser: rejects duplicate keys, invalid escapes/types,
// trailing input and excessive depth/node count before using protocol fields.
struct Parser {
    const std::string& input;
    size_t pos = 0, nodes = 0;
    bool limit = false;
    size_t max_nodes;
    explicit Parser(const std::string& s, size_t maximum = MAX_NODES) : input(s), max_nodes(maximum) {}
    [[noreturn]] void fail() { throw std::runtime_error("invalid JSON"); }
    void ws() { while (pos < input.size() && (input[pos] == ' ' || input[pos] == '\n' ||
        input[pos] == '\r' || input[pos] == '\t')) ++pos; }
    bool take(char c) { if (pos < input.size() && input[pos] == c) { ++pos; return true; } return false; }
    uint32_t hex4() {
        uint32_t cp = 0;
        for (int i = 0; i < 4; ++i) {
            if (pos == input.size()) fail();
            unsigned char c = input[pos++];
            int digit = c >= '0' && c <= '9' ? c - '0' :
                c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            if (digit < 0) fail();
            cp = cp * 16 + digit;
        }
        return cp;
    }
    std::string string() {
        if (!take('"')) fail();
        std::string out;
        while (pos < input.size()) {
            unsigned char c = input[pos++];
            if (c == '"') {
                bool valid = true; normalize(out, valid);
                if (!valid) fail();
                return out;
            }
            if (c < 32) fail();
            if (c != '\\') { out += static_cast<char>(c); continue; }
            if (pos == input.size()) fail();
            switch (input[pos++]) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (!take('\\') || !take('u')) fail();
                        uint32_t low = hex4();
                        if (low < 0xdc00 || low > 0xdfff) fail();
                        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) fail();
                    utf8(out, cp); break;
                }
                default: fail();
            }
        }
        fail();
    }
    Json value(size_t depth = 0) {
        if (depth > MAX_DEPTH || ++nodes > max_nodes) { limit = true; fail(); }
        ws();
        Json result;
        if (pos == input.size()) fail();
        if (input[pos] == '"') { result.kind = 's'; result.text = string(); return result; }
        if (input[pos] == '{' || input[pos] == '[') {
            bool object = input[pos++] == '{';
            result.kind = object ? 'o' : 'a';
            char close = object ? '}' : ']';
            ws(); if (take(close)) return result;
            std::set<std::string> keys;
            size_t index = 0;
            do {
                ws();
                std::string key = object ? string() : std::to_string(index++);
                if (object && !keys.insert(key).second) fail();
                ws(); if (object && !take(':')) fail();
                result.children.emplace_back(key, value(depth + 1));
                ws();
                if (take(close)) return result;
            } while (take(','));
            fail();
        }
        for (const auto& literal : {"true", "false", "null"}) {
            size_t length = std::char_traits<char>::length(literal);
            if (input.compare(pos, length, literal) == 0) {
                pos += length; result.kind = *literal == 'n' ? 'n' : 'b'; result.text = literal; return result;
            }
        }
        size_t start = pos;
        take('-');
        if (!take('0')) {
            if (pos == input.size() || input[pos] < '1' || input[pos] > '9') fail();
            while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) ++pos;
        }
        if (take('.')) {
            size_t digits = pos;
            while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) ++pos;
            if (digits == pos) fail();
        }
        if (take('e') || take('E')) {
            if (!take('+')) take('-');
            size_t digits = pos;
            while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) ++pos;
            if (digits == pos) fail();
        }
        result.kind = 'd'; result.text = input.substr(start, pos - start); return result;
    }
    Json parse() { auto result = value(); ws(); if (pos != input.size()) fail(); return result; }
};

struct Field { std::string scope, path, text; };
struct Input {
    std::vector<Field> fields;
    Json request, response;
    std::string path, host, method, graphql_query, status = "complete";
    bool request_json = false, response_json = false, a2a = false, mcp = false;
};

// Inspect only an actual Bearer JWT header. Never decode arbitrary body text,
// never lower-case the token, and never infer signature validity from its header.
bool jwtHeader(const std::string& authorization, Json& header, bool& limited) {
    size_t start = authorization.find_first_not_of(" \t\r");
    if (start == std::string::npos || authorization.size() - start < 7 ||
        norm(authorization.substr(start, 6)) != "bearer" ||
        (authorization[start + 6] != ' ' && authorization[start + 6] != '\t')) return false;
    start = authorization.find_first_not_of(" \t", start + 6);
    if (start == std::string::npos) return false;
    std::string token = authorization.substr(start);
    size_t end = token.find_last_not_of(" \t\r");
    token.resize(end == std::string::npos ? 0 : end + 1);
    size_t dot = token.find('.');
    if (dot == std::string::npos || dot == 0) return false; // Opaque Bearer token.
    size_t second = token.find('.', dot + 1);
    if (second == std::string::npos || token.find('.', second + 1) != std::string::npos) return false;
    if (dot > 4096) { limited = true; return false; }
    if (dot % 4 == 1) return false;
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string decoded;
    uint32_t buffer = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < dot; ++i) {
        size_t digit = alphabet.find(token[i]);
        if (digit == std::string::npos) return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(digit);
        bits += 6;
        if (bits >= 8) { bits -= 8; decoded += static_cast<char>((buffer >> bits) & 255); }
    }
    if (bits && (buffer & ((1u << bits) - 1))) return false;
    try {
        Parser parser(decoded);
        header = parser.parse();
        return header.kind == 'o';
    } catch (const std::exception&) { return false; }
}

void status(Input& in, const std::string& value) {
    if (in.status == "complete" || value == "limit_exceeded") in.status = value;
}

void addField(Input& in, const std::string& scope, const std::string& path, const std::string& value) {
    if (in.fields.size() >= MAX_FIELDS) { status(in, "limit_exceeded"); return; }
    bool valid = true;
    auto text = normalize(value.substr(0, GUARD_MAX_INPUT), valid);
    if (value.size() > GUARD_MAX_INPUT) status(in, "limit_exceeded");
    if (!valid) status(in, "invalid_utf8");
    if (!text.empty()) in.fields.push_back({scope, path, std::move(text)});
}

void leaves(Input& in, const Json& node, const std::string& scope, const std::string& path) {
    if (node.kind == 's') { addField(in, scope, path, node.text); return; }
    for (const auto& item : node.children) {
        if (in.fields.size() >= MAX_FIELDS) { status(in, "limit_exceeded"); break; }
        // JSON Pointer escapes keep evidence paths unambiguous.
        std::string key;
        for (char c : item.first) key += c == '~' ? "~0" : c == '/' ? "~1" : std::string(1, c);
        std::string next = path + "/" + key;
        if (next.size() > 512) { status(in, "limit_exceeded"); next = scope + "/<path-limit>"; }
        leaves(in, item.second, scope, next);
    }
}

void content(Input& in, const std::string& text, bool response) {
    if (text.empty()) return;
    const std::string scope = response ? "response.text" : "request.text";
    if (text.size() > GUARD_MAX_INPUT) {
        status(in, "limit_exceeded");
        addField(in, scope, scope, text);
        // A large context can hide the instruction at its end. Inspect the
        // bounded tail as a second field instead of dropping it with the
        // rest of the body.
        size_t tail = text.size() - GUARD_MAX_INPUT;
        while (tail < text.size() && (static_cast<unsigned char>(text[tail]) & 0xc0) == 0x80) ++tail;
        addField(in, scope, scope + "/tail", text.substr(tail));
        return;
    }
    auto first = text.find_first_not_of(" \t\r\n");
    if (first != std::string::npos && (text[first] == '{' || text[first] == '[' || text[first] == '"')) {
        Parser parser(text);
        try {
            auto json = parser.parse();
            leaves(in, json, scope, response ? "response" : "request");
            if (response) { in.response = std::move(json); in.response_json = true; }
            else { in.request = std::move(json); in.request_json = true; }
            return;
        } catch (const std::exception&) {
            status(in, parser.limit ? "limit_exceeded" : "malformed_json");
        }
    }
    // Malformed/truncated messages still retain bounded text inspection.
    addField(in, scope, scope, text);
}

std::string decodeUrl(const std::string& text) {
    std::string out;
    bool query = false;
    auto hex = [](char c) { return c >= '0' && c <= '9' ? c - '0' :
        c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '?') query = true;
        if (text[i] == '#') query = false;
        if (text[i] == '%' && i + 2 < text.size() && hex(text[i + 1]) >= 0 && hex(text[i + 2]) >= 0) {
            out += static_cast<char>(hex(text[i + 1]) * 16 + hex(text[i + 2])); i += 2;
        } else out += query && text[i] == '+' ? ' ' : text[i];
    }
    return out;
}

Input prepare(const std::string& method, const std::string& url, const std::string& headers,
              const std::string& body, const std::string& response) {
    Input in;
    in.method = norm(method);
    std::string bounded_url = url.substr(0, GUARD_MAX_INPUT);
    size_t start = 0;
    auto scheme = bounded_url.find("://");
    if (scheme != std::string::npos) {
        start = bounded_url.find_first_of("/?#", scheme + 3);
        auto authority = bounded_url.substr(scheme + 3, start == std::string::npos ? start : start - scheme - 3);
        auto userinfo = authority.rfind('@');
        if (userinfo != std::string::npos) authority.erase(0, userinfo + 1);
        in.host = norm(authority.substr(0, authority.find(':')));
        if (!in.host.empty() && in.host.back() == '.') in.host.pop_back();
    }
    std::string raw_path = start == std::string::npos ? "/" : bounded_url.substr(start);
    in.path = raw_path.substr(0, raw_path.find_first_of("?#"));
    auto query_start = bounded_url.find('?');
    if (query_start != std::string::npos) {
        auto query_end = bounded_url.find('#', query_start);
        auto raw_query = bounded_url.substr(query_start + 1, query_end == std::string::npos ? query_end : query_end - query_start - 1);
        size_t position = 0;
        while (position < raw_query.size()) {
            auto end = raw_query.find('&', position);
            auto parameter = raw_query.substr(position, end == std::string::npos ? end : end - position);
            auto equals = parameter.find('=');
            if (equals != std::string::npos && decodeUrl(parameter.substr(0, equals)) == "query") {
                in.graphql_query = decodeUrl("/?" + parameter.substr(equals + 1)).substr(2);
                break;
            }
            if (end == std::string::npos) break;
            position = end + 1;
        }
    }
    // Route recognition keeps case and reserved separators intact.
    addField(in, "request.url", "request.url", decodeUrl(bounded_url));
    addField(in, "request.host", "request.host", in.host);
    if (url.size() > GUARD_MAX_INPUT || headers.size() > GUARD_MAX_INPUT) status(in, "limit_exceeded");
    std::string bounded_headers;
    if (!apiGuardHeaderLines(headers.substr(0, GUARD_MAX_INPUT), bounded_headers))
        status(in, "malformed_protocol");
    for (size_t begin = 0; begin < bounded_headers.size(); ) {
        size_t end = bounded_headers.find('\n', begin);
        std::string line = bounded_headers.substr(begin, end == std::string::npos ? end : end - begin);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = norm(line.substr(0, colon)), value = norm(line.substr(colon + 1));
            std::string pointer_name;
            for (char c : name) pointer_name += c == '~' ? "~0" : c == '/' ? "~1" : std::string(1, c);
            addField(in, "request.headers", "request.headers/" + pointer_name, line);
            if (name == "a2a-version" || (name == "content-type" &&
                value.substr(0, value.find(';')) == "application/a2a+json")) in.a2a = true;
            if (name == "mcp-session-id" || name == "mcp-protocol-version") in.mcp = true;
            if (name == "host" && in.host.empty()) {
                in.host = value.substr(0, value.find(':'));
                if (!in.host.empty() && in.host.back() == '.') in.host.pop_back();
                addField(in, "request.host", "request.headers/host", in.host);
            }
            if (name == "authorization") {
                Json header;
                bool limited = false;
                if (jwtHeader(line.substr(colon + 1), header, limited)) {
                    addField(in, "request.jwt.alg", "request.headers/authorization/jwt/alg", header.string("alg"));
                    for (const auto& key : {"kid", "jku", "x5u"})
                        addField(in, "request.jwt.header", std::string("request.headers/authorization/jwt/") + key, header.string(key));
                }
                if (limited) status(in, "limit_exceeded");
            }
        }
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    in.mcp = in.mcp || in.path == "/mcp" || in.path.compare(0, 5, "/mcp/") == 0;
    content(in, body, false); content(in, response, true);
    if (in.request_json && in.request.kind == 'a') status(in, "unsupported_batch");
    if (in.request_json && in.request.kind == 'o' && in.request.get("jsonrpc")) {
        const Json* params = in.request.get("params");
        const Json* id = in.request.get("id");
        bool request_envelope = !in.request.string("method").empty() &&
            !in.request.get("result") && !in.request.get("error");
        if (in.request.string("jsonrpc") != "2.0" || !request_envelope ||
            (params && params->kind != 'o' && params->kind != 'a') ||
            (id && id->kind != 's' && id->kind != 'd' && id->kind != 'n'))
            status(in, "malformed_protocol");
    }
    return in;
}

const std::unordered_map<std::string, SignalType>& signalKeys() {
    static const std::unordered_map<std::string, SignalType> keys = {
        {"prompt_injection", SIG_PROMPT_INJECTION}, {"lateral_movement", SIG_LATERAL_MOVEMENT},
        {"tool_abuse", SIG_TOOL_ABUSE}, {"rest_ssrf", SIG_REST_SSRF},
        {"rest_endpoint_probe", SIG_REST_ENDPOINT_PROBE},
        {"rest_data_exfil", SIG_REST_DATA_EXFIL}, {"rest_jwt_abuse", SIG_REST_JWT_ABUSE},
        {"rest_auth_bypass", SIG_REST_AUTH_BYPASS}, {"rest_rate_limit_abuse", SIG_REST_RATE_LIMIT_ABUSE},
        {"corporate_data_context", SIG_CORPORATE_DATA_CONTEXT}, {"ai_provider_usage", SIG_AI_PROVIDER_USAGE},
        {"ai_gateway_context", SIG_AI_GATEWAY_CONTEXT}, {"user_fraud_context", SIG_USER_FRAUD_CONTEXT},
        {"a2a_agent_card_change", SIG_A2A_AGENT_CARD_CHANGE}, {"a2a_unknown_agent", SIG_A2A_UNKNOWN_AGENT},
        {"sqli", SIG_SQLI}, {"xss", SIG_XSS}, {"rce", SIG_RCE}, {"path_traversal", SIG_PATH_TRAVERSAL}
    };
    return keys;
}

// These are structured observations, not independent verification of a card,
// authorization policy or destination trust. Never match JSON key text in quotes.
SignalType a2aEvidence(const Input& in, std::string& field, std::string& id, std::string& reason) {
    const std::string method = in.request.string("method");
    const bool rpc = in.status != "malformed_protocol" && in.request.string("jsonrpc") == "2.0" &&
        (method == "message/send" || method == "message/stream" || method.compare(0, 6, "tasks/") == 0);
    const bool card_route = in.method == "get" && (in.path == "/.well-known/agent-card.json" ||
        in.path == "/.well-known/agent.json" || in.path == "/extendedAgentCard");
    if (!rpc && !in.a2a && !card_route) return SIG_UNKNOWN;
    if (in.status == "malformed_protocol" || in.status == "malformed_json" ||
        in.status == "unsupported_batch") return SIG_UNKNOWN;
    if (!in.response_json || in.response.kind != 'o') return SIG_UNKNOWN;
    if (in.response.get("jsonrpc")) {
        auto response_id = in.response.get("id");
        auto request_id = in.request.get("id");
        if (in.response.string("jsonrpc") != "2.0" || !response_id ||
            (response_id->kind != 's' && response_id->kind != 'd' && response_id->kind != 'n') ||
            (request_id && canonicalJson(*request_id) != canonicalJson(*response_id))) return SIG_UNKNOWN;
    }
    const Json* result = in.response.get("result");
    const Json& value = result && result->kind == 'o' ? *result : in.response;
    const std::string root = result && result->kind == 'o' ? "response/result" : "response";
    auto verdict = [&](SignalType signal, const std::string& path, const std::string& name, const std::string& why) {
        field = path; id = "structured.a2a." + name; reason = why; return signal;
    };
    for (const auto& flag : {"signatureValid", "signature_valid", "signaturevalid", "signedCard", "signedcard",
                             "cardHashChanged", "cardhashchanged", "capabilitiesChanged", "capabilitieschanged"}) {
        auto v = value.get(flag);
        if (v && v->kind == 'b' && v->text == (norm(flag).find("changed") != std::string::npos ? "true" : "false"))
            return verdict(SIG_A2A_AGENT_CARD_CHANGE, root + "/" + flag, "card_change",
                "Observed card integrity/change flag; collector has not verified the signature or baseline");
    }
    const Json* error = in.response.get("error");
    if (error && error->kind == 'o') {
        auto message = norm(error->string("message"));
        for (const auto& phrase : {"unknown agent", "untrusted agent", "agent not found", "agent not registered",
                                  "agent not trusted", "unregistered agent", "unapproved agent"})
            if (message == phrase)
                return verdict(SIG_A2A_UNKNOWN_AGENT, "response/error/message", "unknown_agent",
                    "A2A error reports an unknown or untrusted agent; no local known-agent baseline check");
    }
    const Json* task_status = value.get("status");
    if (task_status && task_status->kind == 'o' &&
        (task_status->string("state") == "auth-required" || task_status->string("state") == "auth_required"))
        return verdict(SIG_A2A_AUTH_REQUIRED, root + "/status/state", "auth_required",
            "A2A task requires authentication; this state alone does not prove abuse");
    auto artifacts = value.get("artifacts");
    if (artifacts && artifacts->kind == 'a') {
        for (size_t i = 0; i < artifacts->children.size(); ++i) {
            auto parts = artifacts->children[i].second.get("parts");
            if (!parts || parts->kind != 'a') continue;
            for (size_t j = 0; j < parts->children.size(); ++j) {
                auto file = parts->children[j].second.get("file");
                if (!file || file->kind != 'o') continue;
                auto uri = norm(file->string("uri"));
                if (uri.compare(0, 7, "http://") == 0 || uri.compare(0, 8, "https://") == 0)
                    return verdict(SIG_A2A_ARTIFACT_EXFIL, root + "/artifacts/" + std::to_string(i) +
                        "/parts/" + std::to_string(j) + "/file/uri", "artifact_transfer",
                        "A2A artifact references an HTTP download destination; confirm destination authorization");
            }
        }
    }
    return SIG_UNKNOWN;
}

bool isContext(SignalType signal) {
    return signal == SIG_CORPORATE_DATA_CONTEXT || signal == SIG_AI_PROVIDER_USAGE ||
        signal == SIG_AI_GATEWAY_CONTEXT || signal == SIG_USER_FRAUD_CONTEXT;
}

// A bounded token inspection, not GraphQL schema validation. Skip quoted and
// block strings, comments and variable names so documentation text is not a
// schema-enumeration observation.
bool graphqlIntrospection(const std::string& query) {
    size_t i = 0;
    auto word = [](unsigned char c) { return std::isalnum(c) || c == '_'; };
    while (i < query.size()) {
        if (query[i] == '#') {
            auto end = query.find('\n', i); i = end == std::string::npos ? query.size() : end + 1; continue;
        }
        if (query[i] == '"') {
            const bool block = query.compare(i, 3, "\"\"\"") == 0;
            i += block ? 3 : 1;
            while (i < query.size()) {
                if (query[i] == '\\') { i = std::min(query.size(), i + 2); continue; }
                if (block ? query.compare(i, 3, "\"\"\"") == 0 : query[i] == '"') {
                    i += block ? 3 : 1; break;
                }
                ++i;
            }
            continue;
        }
        if (word(query[i])) {
            const size_t begin = i;
            while (i < query.size() && word(query[i])) ++i;
            auto token = query.substr(begin, i - begin);
            if ((begin == 0 || query[begin - 1] != '$') && (token == "__schema" || token == "__type")) return true;
        } else ++i;
    }
    return false;
}

SignalType operation(const Input& in, std::string& field, std::string& id) {
    std::string rpc = in.request.string("method");
    const Json* params = in.request.get("params");
    const Json* rpc_id = in.request.get("id");
    bool envelope = in.request.kind == 'o' && in.request.string("jsonrpc") == "2.0" &&
        !rpc.empty() && !in.request.get("result") && !in.request.get("error") &&
        (!params || params->kind == 'o' || params->kind == 'a') &&
        (!rpc_id || rpc_id->kind == 's' || rpc_id->kind == 'd' || rpc_id->kind == 'n');
    const std::unordered_map<std::string, SignalType> mcp = {
        {"initialize", SIG_MCP_HTTP}, {"notifications/initialized", SIG_MCP_HTTP},
        {"notifications/tools/list_changed", SIG_MCP_INVENTORY_CHANGE},
        {"notifications/resources/list_changed", SIG_MCP_INVENTORY_CHANGE},
        {"notifications/prompts/list_changed", SIG_MCP_INVENTORY_CHANGE},
        {"notifications/roots/list_changed", SIG_MCP_INVENTORY_CHANGE},
        {"sampling/createMessage", SIG_MCP_SAMPLING_REQUEST}, {"elicitation/create", SIG_MCP_ELICITATION_REQUEST},
        {"tools/call", SIG_MCP_TOOL_CALL}, {"tools/list", SIG_MCP_TOOL_LIST},
        {"prompts/list", SIG_MCP_INVENTORY_DISCOVERY}, {"resources/templates/list", SIG_MCP_INVENTORY_DISCOVERY},
        {"prompts/get", SIG_MCP_PROMPT_ACCESS}, {"resources/read", SIG_MCP_RESOURCE_ACCESS},
        {"completion/complete", SIG_MCP_INVENTORY_DISCOVERY},
        {"resources/list", SIG_MCP_RESOURCE_ACCESS}, {"resources/subscribe", SIG_MCP_RESOURCE_ACCESS},
        {"resources/unsubscribe", SIG_MCP_RESOURCE_ACCESS}, {"roots/list", SIG_MCP_RESOURCE_ACCESS}
    };
    const std::unordered_map<std::string, SignalType> a2a = {
        {"message/send", SIG_A2A_MESSAGE_SEND}, {"message/stream", SIG_A2A_MESSAGE_SEND},
        {"tasks/get", SIG_A2A_TASK_ACCESS}, {"tasks/list", SIG_A2A_TASK_ACCESS},
        {"tasks/resubscribe", SIG_A2A_TASK_ACCESS}, {"tasks/cancel", SIG_A2A_TASK_CANCEL},
        {"tasks/pushNotificationConfig/set", SIG_A2A_PUSH_NOTIFICATION},
        {"tasks/pushNotificationConfig/get", SIG_A2A_PUSH_NOTIFICATION},
        {"tasks/pushNotificationConfig/list", SIG_A2A_PUSH_NOTIFICATION},
        {"tasks/pushNotificationConfig/delete", SIG_A2A_PUSH_NOTIFICATION}
    };
    if (envelope) {
        auto a = a2a.find(rpc);
        if (a != a2a.end()) { field = "request/method"; id = "protocol.a2a." + rpc; return a->second; }
        auto m = mcp.find(rpc);
        if (envelope && !in.a2a && m != mcp.end()) {
            field = "request/method"; id = "protocol.mcp." + rpc; return m->second;
        }
        // Legacy server extensions require explicit MCP transport context;
        // quoted spellings and unrelated generic JSON-RPC are not operations.
        if (in.mcp && !in.a2a) {
            const std::unordered_map<std::string, SignalType> legacy = {
                {"sampling/create_message", SIG_MCP_SAMPLING_REQUEST},
                {"sampling/create-message", SIG_MCP_SAMPLING_REQUEST},
                {"elicitation/request", SIG_MCP_ELICITATION_REQUEST},
                {"prompts/subscribe", SIG_MCP_PROMPT_ACCESS},
                {"tools/list_changed", SIG_MCP_INVENTORY_CHANGE},
                {"resources/list_changed", SIG_MCP_INVENTORY_CHANGE},
                {"prompts/list_changed", SIG_MCP_INVENTORY_CHANGE},
                {"roots/list_changed", SIG_MCP_INVENTORY_CHANGE}
            };
            auto extension = legacy.find(rpc);
            if (extension != legacy.end()) {
                field = "request/method"; id = "protocol.mcp.extension." + rpc;
                return extension->second;
            }
        }
    }
    field = "request.url";
    if (in.method == "get" && (in.path == "/.well-known/agent-card.json" ||
        in.path == "/.well-known/agent.json" || in.path == "/extendedAgentCard")) { id = "protocol.a2a.card"; return SIG_A2A_AGENT_CARD_DISCOVERY; }
    if (in.method == "post" && (in.path == "/message:send" || in.path == "/message:stream")) {
        id = "protocol.a2a.message"; return SIG_A2A_MESSAGE_SEND;
    }
    if (in.path == "/tasks" || in.path.compare(0, 7, "/tasks/") == 0) {
        if (in.method == "post" && in.path.size() > 7 &&
            in.path.compare(in.path.size() - 7, 7, ":cancel") == 0) {
            id = "protocol.a2a.cancel"; return SIG_A2A_TASK_CANCEL;
        }
        if (in.method == "get") { id = "protocol.a2a.task"; return SIG_A2A_TASK_ACCESS; }
    }
    if (in.a2a) { field = "request.headers"; id = "protocol.a2a.transport"; return SIG_A2A_HTTP; }
    if (in.mcp) { id = "protocol.mcp.transport"; return SIG_MCP_HTTP; }
    return SIG_UNKNOWN;
}

void checkKeys(const YAML::Node& node, const std::set<std::string>& allowed) {
    if (!node.IsMap()) throw std::runtime_error("expected mapping");
    std::set<std::string> seen;
    for (const auto& entry : node) {
        auto key = entry.first.as<std::string>();
        if (!allowed.count(key) || !seen.insert(key).second)
            throw std::runtime_error("unknown or duplicate key: " + key);
    }
}
std::string scalar(const YAML::Node& node, const std::string& name, size_t max) {
    if (!node.IsScalar()) throw std::runtime_error(name + " must be a scalar");
    auto value = node.as<std::string>();
    if (value.empty() || value.size() > max) throw std::runtime_error(name + " has invalid length");
    return value;
}
} // namespace

bool apiGuardHeaderLines(const std::string& input, std::string& output) {
    output.clear();
    if (input.size() > GUARD_MAX_INPUT) return false;
    auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos || (input[first] != '{' && input[first] != '[')) {
        output = input;
        return true;
    }
    Json root;
    if (!parseBoundedJson(input, root)) return false;
    const Json* array = root.kind == 'a' ? &root : root.get("http_headers");
    std::vector<std::pair<std::string, std::string>> fields;
    if (array) {
        if (array->kind != 'a' || array->children.size() > MAX_FIELDS) return false;
        for (const auto& entry : array->children) {
            auto name = entry.second.get("name"), value = entry.second.get("value");
            if (!name || !value || name->kind != 's' || value->kind != 's') return false;
            fields.emplace_back(name->text, value->text);
        }
    } else if (root.kind == 'o') {
        if (root.children.size() > MAX_FIELDS) return false;
        for (const auto& entry : root.children) {
            if (entry.second.kind != 's') return false;
            fields.emplace_back(entry.first, entry.second.text);
        }
    } else return false;
    for (const auto& field : fields) {
        if (field.first.empty() || field.first.find_first_of(":\r\n") != std::string::npos ||
            field.second.find_first_of("\r\n") != std::string::npos) {
            output.clear();
            return false;
        }
        output += field.first + ": " + field.second + "\r\n";
    }
    return true;
}

bool parseBoundedJson(const std::string& text, Json& out, size_t max_bytes, size_t max_nodes) {
    if (text.empty() || text.size() > max_bytes) return false;
    try { out = Parser(text, max_nodes).parse(); return true; }
    catch (const std::exception&) { return false; }
}

std::string canonicalJson(const Json& value) {
    // Length prefixes make this an unambiguous typed comparison key, rather
    // than JSON for display. Object key order does not affect equality.
    std::string out(1, value.kind);
    if (value.kind == 'd') {
        // Compare equivalent decimal spellings exactly without floating-point
        // rounding or expanding large exponents into enormous strings.
        const auto exponent_pos = value.text.find_first_of("eE");
        std::string mantissa = value.text.substr(0, exponent_pos);
        std::string exponent = exponent_pos == std::string::npos ? "0" : value.text.substr(exponent_pos + 1);
        if (exponent.size() <= 10) {
            long long power = std::stoll(exponent);
            bool negative = !mantissa.empty() && mantissa[0] == '-';
            if (negative) mantissa.erase(0, 1);
            auto dot = mantissa.find('.');
            if (dot != std::string::npos) {
                power -= static_cast<long long>(mantissa.size() - dot - 1);
                mantissa.erase(dot, 1);
            }
            auto start = mantissa.find_first_not_of('0');
            if (start == std::string::npos) return "d0";
            mantissa.erase(0, start);
            while (mantissa.size() > 1 && mantissa.back() == '0') { mantissa.pop_back(); ++power; }
            return "d" + std::string(negative ? "-" : "") + mantissa + "e" + std::to_string(power);
        }
    }
    if (value.kind != 'o' && value.kind != 'a')
        return out + std::to_string(value.text.size()) + ":" + value.text;
    std::vector<std::pair<std::string, std::string>> items;
    for (const auto& child : value.children)
        items.emplace_back(child.first, canonicalJson(child.second));
    if (value.kind == 'o') std::sort(items.begin(), items.end());
    for (const auto& item : items) {
        if (value.kind == 'o') out += std::to_string(item.first.size()) + ":" + item.first;
        out += std::to_string(item.second.size()) + ":" + item.second;
    }
    return out;
}

ApiGuard::Ruleset ApiGuard::defaults() {
    Ruleset out;
    // Committed generated data keeps fallback and packaged YAML identical.
#include "api_guard_rules.inc"
    return out;
}

ApiGuard::ApiGuard() : ruleset(std::make_shared<const Ruleset>(defaults())) {}

bool ApiGuard::load(const std::string& path) {
    if (path.empty()) {
        probeDiagnostic((char*)"[ApiGuard] no configured path; retaining active ruleset");
        return true;
    }
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot open rules file");
        std::string source;
        char ch;
        while (file.get(ch)) {
            if (source.size() >= MAX_CONFIG) throw std::runtime_error("rules file exceeds size limit");
            source += ch;
        }
        YAML::Node root = YAML::Load(source);
        checkKeys(root, {"schema_version", "ruleset_version", "rules"});
        if (!root["schema_version"].IsScalar() || root["schema_version"].as<int>() != 2)
            throw std::runtime_error("schema_version: 2 required; migrate legacy substring lists");
        Ruleset candidate;
        candidate.version = scalar(root["ruleset_version"], "ruleset_version", 64);
        auto entries = root["rules"];
        if (!entries.IsSequence() || entries.size() == 0 || entries.size() > 128)
            throw std::runtime_error("rules must contain 1..128 entries");
        std::set<std::string> ids;
        for (const auto& entry : entries) {
            checkKeys(entry, {"id", "kind", "signal", "fields", "tools", "all", "window", "confidence", "reason"});
            Rule rule;
            rule.id = scalar(entry["id"], "id", 96);
            if (!ids.insert(rule.id).second) throw std::runtime_error("duplicate rule id: " + rule.id);
            rule.kind = scalar(entry["kind"], "kind", 16);
            if (rule.kind != "threat" && rule.kind != "context") throw std::runtime_error("invalid rule kind");
            auto signal = scalar(entry["signal"], "signal", 64);
            auto found = signalKeys().find(signal);
            if (found == signalKeys().end()) throw std::runtime_error("unsupported signal: " + signal);
            rule.signal = found->second;
            if ((rule.kind == "context") != isContext(rule.signal)) throw std::runtime_error("signal/kind mismatch");
            rule.reason = scalar(entry["reason"], "reason", 256);
            if (entry["tools"]) {
                auto tools = entry["tools"];
                if (!tools.IsSequence() || !tools.size() || tools.size() > 32)
                    throw std::runtime_error("tools must contain 1..32 exact names");
                for (const auto& tool : tools) rule.tools.push_back(scalar(tool, "tool", 128));
            }
            auto fields = entry["fields"];
            if (!fields.IsSequence() || !fields.size() || fields.size() > 7) throw std::runtime_error("invalid fields");
            std::set<std::string> seen_fields;
            for (const auto& f : fields) {
                auto field = scalar(f, "field", 32);
                if (field != "request.text" && field != "response.text" && field != "request.url" &&
                    field != "request.headers" && field != "request.host" && field != "request.jwt.alg" &&
                    field != "request.jwt.header")
                    throw std::runtime_error("unknown field: " + field);
                if (!seen_fields.insert(field).second) throw std::runtime_error("duplicate field");
                rule.fields.push_back(field);
            }
            rule.window = entry["window"] ? entry["window"].as<size_t>() : 160;
            rule.confidence = entry["confidence"] ? entry["confidence"].as<int>() : 80;
            if (rule.window < 16 || rule.window > 512 || rule.confidence < 1 || rule.confidence > 100)
                throw std::runtime_error("invalid window/confidence");
            auto groups = entry["all"];
            if (!groups.IsSequence() || !groups.size() || groups.size() > 8) throw std::runtime_error("invalid all groups");
            for (const auto& group : groups) {
                if (!group.IsSequence() || !group.size() || group.size() > 32) throw std::runtime_error("invalid alternatives");
                std::vector<std::string> terms;
                for (const auto& term : group) {
                    auto value = scalar(term, "term", 128);
                    bool valid = true; value = normalize(value, valid);
                    if (!valid || value.empty() || value.size() > rule.window)
                        throw std::runtime_error("invalid normalized term");
                    if (std::find(terms.begin(), terms.end(), value) == terms.end()) terms.push_back(value);
                }
                rule.all.push_back(std::move(terms));
            }
            candidate.rules.push_back(std::move(rule));
        }
        // Readers keep their old snapshot until inspection completes.
        std::atomic_store(&ruleset, std::make_shared<const Ruleset>(std::move(candidate)));
        std::string message = "[ApiGuard] activated ruleset " + std::atomic_load(&ruleset)->version;
        probeDiagnostic((char*)message.c_str());
        return true;
    } catch (const std::exception& error) {
        std::string message = "[ApiGuard] rejected configuration; retaining active ruleset: " + path + " error=" + error.what();
        probeDiagnostic((char*)message.c_str());
        return false;
    }
}

SignalType ApiGuard::inspect(const std::string& method, const std::string& url,
    const std::string& headers, const std::string& body, const std::string& response,
    bool rest_only, GuardMatch* detail) const {
    auto snapshot = std::atomic_load(&ruleset);
    Input in = prepare(method, url, headers, body, response);
    GuardMatch result;
    result.ruleset_version = snapshot->version;
    result.inspection_status = in.status;
    auto finish = [&](SignalType signal) {
        result.signal = signalName(signal);
        if (detail) *detail = result;
        return signal;
    };
    size_t search_steps = 0;
    size_t searched_bytes = 0;
    constexpr size_t search_byte_limit = 64 * 1024 * 1024;
    std::string tool;
    if (in.status != "malformed_protocol" && in.request.string("jsonrpc") == "2.0" &&
        in.request.string("method") == "tools/call" && !in.request.get("result") && !in.request.get("error")) {
        const Json* params = in.request.get("params");
        if (params) tool = params->string("name");
    }
    auto matchRules = [&](const std::string& kind) {
        for (const auto& rule : snapshot->rules) {
            if (rule.kind != kind) continue;
            if (!rule.tools.empty() && std::find(rule.tools.begin(), rule.tools.end(), tool) == rule.tools.end()) continue;
            if (rest_only && (rule.signal == SIG_PROMPT_INJECTION || rule.signal == SIG_TOOL_ABUSE ||
                rule.signal == SIG_LATERAL_MOVEMENT)) continue;
            for (const auto& field : in.fields) {
                if (std::find(rule.fields.begin(), rule.fields.end(), field.scope) == rule.fields.end()) continue;
                std::vector<std::string> evidence;
                bool hit = false;
                if (field.scope == "request.host" || field.scope == "request.jwt.alg") {
                    // Host rules are exact/suffix domain matches, not substring matches.
                    bool all = true;
                    for (const auto& group : rule.all) {
                        bool any = false;
                        for (const auto& term : group) {
                            if (field.text == term || (field.scope == "request.host" && field.text.size() > term.size() &&
                                field.text.compare(field.text.size() - term.size(), term.size(), term) == 0 &&
                                field.text[field.text.size() - term.size() - 1] == '.')) {
                                evidence.push_back(term); any = true; break;
                            }
                        }
                        if (!any) { all = false; break; }
                    }
                    hit = all;
                } else {
                    // Sliding spans find all groups without a greedy choice of
                    // alternatives. Never combine different JSON scalar fields.
                    struct Hit { size_t begin, end, group; std::string term; };
                    std::vector<Hit> hits;
                    for (size_t g = 0; g < rule.all.size(); ++g) {
                        for (const auto& term : rule.all[g]) {
                            size_t pos = 0;
                            while (pos < field.text.size()) {
                                if (++search_steps > 65536 || hits.size() >= 4096) {
                                    status(in, "limit_exceeded"); break;
                                }
                                size_t available = std::min(field.text.size() - pos, search_byte_limit - searched_bytes);
                                std::string_view slice(field.text.data() + pos, available);
                                size_t found = slice.find(term);
                                searched_bytes += found == std::string_view::npos ? available : found + term.size();
                                if (found == std::string_view::npos) {
                                    if (available < field.text.size() - pos) {
                                        status(in, "limit_exceeded"); search_steps = 65537;
                                    }
                                    break;
                                }
                                pos += found;
                                if (termAt(field.text, term, pos)) hits.push_back({pos, pos + term.size(), g, term});
                                ++pos;
                            }
                            if (search_steps > 65536 || hits.size() >= 4096) break;
                        }
                        if (search_steps > 65536 || hits.size() >= 4096) break;
                    }
                    std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.begin < b.begin; });
                    std::vector<size_t> counts(rule.all.size(), 0);
                    std::multiset<size_t> ends;
                    size_t left = 0, present = 0;
                    for (size_t right = 0; right < hits.size(); ++right) {
                        if (counts[hits[right].group]++ == 0) ++present;
                        ends.insert(hits[right].end);
                        while (!ends.empty() && *ends.rbegin() - hits[left].begin > rule.window) {
                            if (--counts[hits[left].group] == 0) --present;
                            ends.erase(ends.find(hits[left].end)); ++left;
                        }
                        if (present == rule.all.size()) {
                            evidence.resize(rule.all.size());
                            for (size_t i = left; i <= right; ++i)
                                if (evidence[hits[i].group].empty()) evidence[hits[i].group] = hits[i].term;
                            hit = true; break;
                        }
                    }
                }
                if (hit) {
                    result.kind = rule.kind;
                    result.rule_id = rule.id; result.field = field.path; result.reason = rule.reason;
                    result.confidence = rule.confidence; result.matched_terms = std::move(evidence);
                    return rule.signal;
                }
                if (search_steps > 65536) return SIG_UNKNOWN;
            }
        }
        return SIG_UNKNOWN;
    };
    auto signal = matchRules("threat");
    result.inspection_status = in.status;
    if (signal != SIG_UNKNOWN) return finish(signal);
    if (!rest_only) {
        std::string field, id;
        std::string reason;
        signal = a2aEvidence(in, field, id, reason);
        if (signal != SIG_UNKNOWN) {
            result.kind = "protocol";
            result.rule_id = id; result.field = field; result.reason = reason;
            result.confidence = 75; return finish(signal);
        }
        signal = operation(in, field, id);
        if (signal != SIG_UNKNOWN) {
            result.kind = "protocol";
            result.rule_id = id; result.field = field;
            result.reason = "Structured protocol activity; not an attack verdict";
            result.confidence = 95; return finish(signal);
        }
    }
    // Dedicated discovery paths are observations. Ordinary /api GET requests
    // remain REST activity rather than reconnaissance findings.
    if (in.method == "get" || in.method == "head" || in.method == "options" ||
        (in.method == "post" && in.path == "/graphql")) {
        const std::set<std::string> discovery = {"/swagger", "/swagger.json", "/swagger/v1/swagger.json",
            "/openapi", "/openapi.json", "/openapi.yaml", "/api-docs", "/docs", "/redoc",
            "/actuator", "/actuator/env", "/actuator/heapdump", "/debug", "/metrics"};
        std::string field;
        if (discovery.count(in.path)) field = "request.url";
        if (in.path == "/graphql") {
            if (graphqlIntrospection(in.request.string("query")))
                field = "request/query";
            else if (in.method == "get" && graphqlIntrospection(in.graphql_query)) field = "request.url";
        }
        if (!field.empty()) {
            result.kind = "protocol"; result.rule_id = "protocol.rest.discovery";
            result.field = field; result.reason = "API schema/debug discovery activity; confirm authorization";
            result.confidence = 65; return finish(SIG_REST_ENDPOINT_PROBE);
        }
    }
    // Retain export/download workflow observation without treating an archive
    // extension or an arbitrary mention of "export" as proven exfiltration.
    if ((in.method == "get" || in.method == "post") &&
        (in.path == "/api/export" || in.path == "/api/download" || in.path == "/api/backup" ||
         in.path == "/api/dump" || in.path == "/api/data/bulk")) {
        result.kind = "protocol"; result.rule_id = "protocol.rest.bulk_activity";
        result.field = "request.url";
        result.reason = "Bulk export/download workflow activity; not proof of unauthorized data transfer";
        result.confidence = 65; return finish(SIG_REST_DATA_EXFIL);
    }
    signal = matchRules("context");
    result.inspection_status = in.status;
    if (signal != SIG_UNKNOWN) return finish(signal);
    if (in.path.compare(0, 5, "/api/") == 0 || in.path.compare(0, 4, "/v1/") == 0 ||
        in.path.compare(0, 4, "/v2/") == 0 || in.path.compare(0, 4, "/v3/") == 0 ||
        in.path.compare(0, 6, "/rest/") == 0 || in.path.compare(0, 9, "/wp-json/") == 0 || in.path == "/graphql") {
        result.rule_id = "protocol.rest.activity"; result.field = "request.url";
        result.kind = "protocol";
        result.reason = "API route activity; a single request is not endpoint probing";
        result.confidence = 70; return finish(SIG_REST_API_CALL);
    }
    return finish(SIG_UNKNOWN);
}

SignalType ApiGuard::classifyHttpMcpSignal(const std::string& method, const std::string& url,
    const std::string& headers, const std::string& body, const std::string& response, GuardMatch* detail) const {
    return inspect(method, url, headers, body, response, false, detail);
}
SignalType ApiGuard::classifyRestSignal(const std::string& method, const std::string& url,
    const std::string& headers, const std::string& body, const std::string& response, GuardMatch* detail) const {
    return inspect(method, url, headers, body, response, true, detail);
}
