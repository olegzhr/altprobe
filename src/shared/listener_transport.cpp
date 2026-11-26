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

#include "listener_transport.h"
#include <boost/asio/ip/address.hpp>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <stdexcept>

std::string listenerReadFile(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("cannot read policy TLS file");
    return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

bool listenerPeerAllowed(const std::string& raw, const HttpListenerConfig& c) {
    boost::system::error_code ec; auto address = boost::asio::ip::make_address(raw, ec);
    if (ec) return false;
    if (address.is_v6() && address.to_v6().is_v4_mapped()) {
        const auto bytes = address.to_v6().to_bytes();
        address = boost::asio::ip::address_v4(
            boost::asio::ip::address_v4::bytes_type{bytes[12], bytes[13], bytes[14], bytes[15]});
    }
    return std::find(c.trusted_peers.begin(), c.trusted_peers.end(), address.to_string()) != c.trusted_peers.end();
}

