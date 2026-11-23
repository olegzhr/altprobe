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

#include "collector_config.h"
#include "cobject.h"
#include <cassert>
#include <cstdlib>

int main() {
    std::string error;
    setenv("ALTPROBE_GATEWAY_TYPE", "higress", 1);
    setenv("SINKS_ALERTFLEX_INCIDENT_ENABLED", "true", 1);
    setenv("SINKS_ALERTFLEX_TIMEOUT_MS", "5000", 1);
    setenv("SINKS_ALERTFLEX_MAX_PENDING", "512", 1);
    setenv("SINKS_ALERTFLEX_ALLOW_HTTP", "false", 1);
    unsetenv("POLICY_ENABLED");
    assert(loadCollectorSettings(2, error));
    assert(CObject::gateway_type == "higress" && CObject::incident_enabled);
    // Invalid config fails cleanly and cannot partially publish new state.
    setenv("SINKS_ALERTFLEX_TIMEOUT_MS", "5000oops", 1);
    assert(!loadCollectorSettings(2, error));
    assert(CObject::incident_timeout_ms == 5000 && CObject::incident_enabled);
    setenv("SINKS_ALERTFLEX_TIMEOUT_MS", "5000", 1);
    setenv("SINKS_ALERTFLEX_INCIDENT_ENABLED", "typo", 1);
    assert(!loadCollectorSettings(2, error));
    setenv("SINKS_ALERTFLEX_INCIDENT_ENABLED", "true", 1);
    // A formerly combined deployment must move its authz config explicitly.
    setenv("POLICY_ENABLED", "true", 1);
    assert(!loadCollectorSettings(2, error));
    unsetenv("POLICY_ENABLED");
    setenv("ALTPROBE_GATEWAY_TYPE", "unknown", 1);
    assert(!loadCollectorSettings(2, error));
    setenv("ALTPROBE_GATEWAY_TYPE", "apisix", 1);
    assert(loadCollectorSettings(2, error));

    unsetenv("SINKS_AF_TLS_VERIFY");
    unsetenv("SINKS_OS_TLS_VERIFY");
    unsetenv("SINKS_SPLUNK_TLS_VERIFY");
    unsetenv("SINKS_GRAYLOG_TLS_VERIFY");
    CObject settings;
    CObject::run_mode = 2;
    assert(settings.GetConfig(2));
    assert(CObject::af_tls_verify && CObject::os_tls_verify && CObject::splunk_tls_verify && CObject::graylog_tls_verify);
}
