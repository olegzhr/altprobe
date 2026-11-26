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

#ifndef ALTPROBE_HTTP_IO_H
#define ALTPROBE_HTTP_IO_H

#include "cobject.h"
#include "tls_client.h"
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <thread>

namespace bounded_http {
namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = net::ip::tcp;
using Clock = std::chrono::steady_clock;

// Run asynchronous I/O on the owning worker, with one absolute deadline.
// Cancellation is executed on that same worker; callbacks cannot outlive locals.
template<class Start, class Cancel, class Stopped>
beast::error_code perform(net::io_context& ioc, Clock::time_point deadline,
                          Stopped stopped, Start start, Cancel cancel) {
    if (stopped()) return net::error::operation_aborted;
    if (Clock::now() >= deadline) return beast::error::timeout;
    bool done = false, cancelled = false;
    beast::error_code result, forced;
    ioc.restart();
    start([&](beast::error_code ec, auto...) { result = ec; done = true; });
    while (!done) {
        if (!cancelled && (stopped() || Clock::now() >= deadline)) {
            forced = stopped() ? beast::error_code(net::error::operation_aborted)
                               : beast::error_code(beast::error::timeout);
            cancelled = true;
            cancel();
        }
        ioc.restart();
        ioc.run_for(std::chrono::milliseconds(25));
    }
    return forced ? forced : result;
}

inline std::shared_ptr<std::atomic<unsigned>> resolverCapacity() {
    static const auto capacity = std::make_shared<std::atomic<unsigned>>(0);
    return capacity;
}

// System getaddrinfo may ignore Asio cancellation once a lookup has started.
// Keep that work off the request thread with independent lifetime and at most
// four outstanding lookups. A stuck resolver cannot defeat the request deadline
// or spawn an unbounded number of background threads.
template<class Stopped>
tcp::resolver::results_type resolve(const std::string& host, const std::string& port,
        Clock::time_point deadline, Stopped stopped) {
    struct State {
        std::mutex mutex;
        std::condition_variable ready;
        bool done = false;
        beast::error_code error;
        tcp::resolver::results_type endpoints;
    };
    const auto active = resolverCapacity();
    if (stopped()) throw beast::system_error(net::error::operation_aborted);
    if (Clock::now() >= deadline) throw beast::system_error(beast::error::timeout);
    auto state = std::make_shared<State>();
    if (active->fetch_add(1) >= 4) {
        --*active;
        throw beast::system_error(net::error::no_buffer_space);
    }
    auto capacity = active;
    try {
        std::thread([state, capacity, host, port] {
            beast::error_code error;
            tcp::resolver::results_type endpoints;
            try {
                net::io_context context;
                tcp::resolver resolver(context);
                endpoints = resolver.resolve(host, port, error);
            } catch (...) { error = net::error::host_not_found; }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->error = error;
                state->endpoints = std::move(endpoints);
                state->done = true;
            }
            --*capacity;
            state->ready.notify_one();
        }).detach();
    } catch (...) { --*capacity; throw; }
    std::unique_lock<std::mutex> lock(state->mutex);
    while (!state->done) {
        if (stopped()) throw beast::system_error(net::error::operation_aborted);
        if (Clock::now() >= deadline) throw beast::system_error(beast::error::timeout);
        state->ready.wait_until(lock, std::min(deadline, Clock::now() + std::chrono::milliseconds(25)));
    }
    if (stopped()) throw beast::system_error(net::error::operation_aborted);
    if (Clock::now() >= deadline) throw beast::system_error(beast::error::timeout);
    if (state->error) throw beast::system_error(state->error);
    return state->endpoints;
}

inline http::response<http::string_body> request(
    bool https, const std::string& host, const std::string& port,
    const std::string& target, const std::string& method, const std::string& body,
    const std::string& auth, const std::map<std::string, std::string>& headers,
    const std::string& contentType, std::chrono::milliseconds timeout = std::chrono::seconds(60),
    std::function<bool()> additionalStop = {}, size_t responseLimit = 8 * 1024 * 1024,
    bool tlsVerify = false, const std::string& tlsCaFile = "") {
    net::io_context ioc;
    const auto deadline = Clock::now() + timeout;
    auto stopped = [&] { return CObject::stopping.load() || (additionalStop && additionalStop()); };
    auto check = [](beast::error_code ec) { if (ec) throw beast::system_error(ec); };
    const auto endpoints = resolve(host, port, deadline, stopped);
    http::request<http::string_body> req{http::string_to_verb(method), target, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, "Altprobe");
    if (!contentType.empty()) req.set(http::field::content_type, contentType);
    if (!auth.empty()) req.set(http::field::authorization, auth);
    for (const auto& h : headers) req.set(h.first, h.second);
    req.body() = body;
    req.prepare_payload();
    http::response<http::string_body> response;
    auto exchange = [&](auto& stream) {
        auto cancel = [&] { beast::error_code ec; beast::get_lowest_layer(stream).socket().close(ec); };
        check(perform(ioc, deadline, stopped, [&](auto done) { http::async_write(stream, req, done); }, cancel));
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(responseLimit);
        parser.header_limit(8192);
        check(perform(ioc, deadline, stopped, [&](auto done) { http::async_read(stream, buffer, parser, done); }, cancel));
        response = parser.release();
    };
    if (https) {
        net::ssl::context ctx(net::ssl::context::tlsv12_client);
        tls_client::configure(ctx, tlsVerify, tlsCaFile);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
        tls_client::verifyHost(stream, tlsVerify, host);
        auto cancel = [&] { beast::error_code ec; beast::get_lowest_layer(stream).socket().close(ec); };
        if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
            throw std::runtime_error("cannot set TLS server name");
        check(perform(ioc, deadline, stopped, [&](auto done) { beast::get_lowest_layer(stream).async_connect(endpoints, done); }, cancel));
        check(perform(ioc, deadline, stopped, [&](auto done) { stream.async_handshake(net::ssl::stream_base::client, done); }, cancel));
        exchange(stream);
        // The response is already complete. Bound TLS close_notify separately
        // so a peer that never closes cannot stall a successful delivery.
        perform(ioc, std::min(deadline, Clock::now() + std::chrono::seconds(1)), stopped,
                [&](auto done) { stream.async_shutdown(done); }, cancel);
    } else {
        beast::tcp_stream stream(ioc);
        auto cancel = [&] { beast::error_code ec; stream.socket().close(ec); };
        check(perform(ioc, deadline, stopped, [&](auto done) { stream.async_connect(endpoints, done); }, cancel));
        exchange(stream);
    }
    return response;
}
}
#endif
