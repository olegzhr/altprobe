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

#ifndef ALTPROBE_TLS_CLIENT_H
#define ALTPROBE_TLS_CLIENT_H

#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <string>

namespace tls_client {
inline void configure(boost::asio::ssl::context& context, bool verify,
                      const std::string& ca_file) {
    context.set_verify_mode(verify ? boost::asio::ssl::verify_peer : boost::asio::ssl::verify_none);
    if (verify) {
        context.set_default_verify_paths();
        if (!ca_file.empty()) context.load_verify_file(ca_file);
    }
}

template<class Stream>
inline void verifyHost(Stream& stream, bool verify, const std::string& host) {
    // Checks DNS SAN / IP SAN in addition to OpenSSL chain and validity checks.
    if (verify) stream.set_verify_callback(boost::asio::ssl::host_name_verification(host));
}
}
#endif
