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

#include "http_io.h"
#include <cassert>
#include <atomic>
#include <thread>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Accept and drain bytes but never return HTTP headers or a TLS handshake.
// Nonblocking server I/O makes fixture teardown independent of client behavior.
class SilentPeer {
    int listener_;
    std::atomic<bool> stop_{false};
    std::thread worker_;
public:
    std::string port;
    SilentPeer() {
        listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
        assert(listener_ >= 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        assert(::listen(listener_, 1) == 0);
        socklen_t length = sizeof(address);
        assert(::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        port = std::to_string(ntohs(address.sin_port));
        assert(::fcntl(listener_, F_SETFL, O_NONBLOCK) == 0);
        worker_ = std::thread([this] {
            int client = -1;
            while (!stop_) {
                if (client < 0) {
                    client = ::accept(listener_, nullptr, nullptr);
                    if (client >= 0) ::fcntl(client, F_SETFL, O_NONBLOCK);
                }
                if (client >= 0) { char bytes[4096]; ::recv(client, bytes, sizeof(bytes), 0); }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            if (client >= 0) ::close(client);
        });
    }
    ~SilentPeer() { stop_ = true; worker_.join(); ::close(listener_); }
};

int main() {
    CObject::stopping = false;
    for (bool https : {false, true}) {
        SilentPeer peer;
        const auto start = bounded_http::Clock::now();
        bool timedOut = false;
        try {
            bounded_http::request(https, "127.0.0.1", peer.port, "/", "GET", "", "", {}, "",
                    std::chrono::milliseconds(200));
        } catch (const boost::system::system_error& error) {
            timedOut = error.code() == boost::beast::error::timeout;
        }
        assert(timedOut);
        assert(bounded_http::Clock::now() - start < std::chrono::seconds(3));
    }
    {
        SilentPeer peer;
        const auto start = bounded_http::Clock::now();
        bool cancelled = false;
        try {
            bounded_http::request(false, "127.0.0.1", peer.port, "/", "GET", "", "", {}, "",
                    std::chrono::seconds(5), [&] {
                        return bounded_http::Clock::now() - start >= std::chrono::milliseconds(50);
                    });
        } catch (const boost::system::system_error& error) {
            cancelled = error.code() == boost::asio::error::operation_aborted;
        }
        assert(cancelled);
        assert(bounded_http::Clock::now() - start < std::chrono::seconds(3));
    }
    std::cout << "PASS HTTP read/TLS handshake deadlines and shutdown cancellation\n";
}
