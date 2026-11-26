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

#ifndef LLM_GUARD_H
#define LLM_GUARD_H

#include "source.h"
#include "http.h"
#include "detection.h"
#include <deque>
#include <mutex>

struct LlmGuardConfig {
    bool enabled = false, inspect_request = true, inspect_response = true;
    bool tls_verify = true;
    std::string provider = "ollama", url = "http://127.0.0.1:11434", model,
        format = "qwen3guard", config_id, ca_file;
    int timeout_ms = 10000, max_body_bytes = 16384, queue_size = 128;
};

// Pure helpers shared by the worker and native regression tests.
std::string llmGuardPayload(const LlmGuardConfig&, const std::string& request,
                               const std::string& response, bool response_check);
LlmGuardMatch parseLlmGuardVerdict(const std::string& content, const std::string& format);
LlmGuardMatch parseGuardNemoVerdict(const std::string& response);
void mergeLlmGuardVerdict(Event& event, const LlmGuardMatch& verdict);

// Optional asynchronous content inspection. Multiple sensor producers share a
// bounded, mutex-protected queue; slow model calls never run on sensor threads.
// A model verdict is detection evidence, not a trusted gateway identity.
class LlmGuard : public Source {
public:
    bool GetConfig(int mode) override;
    bool Open() override;
    void Close() override;
    bool Go() override;
    void Submit(const Http& http, const std::string& sensor);
private:
    struct Job {
        Http http; std::string sensor; size_t request_size, response_size;
        GuardMatch request_guard, response_guard;
        SignalType request_signal = SIG_UNKNOWN, response_signal = SIG_UNKNOWN;
    };
    LlmGuardConfig config_;
    std::string host_, port_, base_path_;
    bool https_ = false;
    std::atomic<bool> accepting_{false};
    std::mutex queue_mutex_;
    std::deque<Job> queue_;
    unsigned long dropped_ = 0;
    void Inspect(const Job& job, bool response_check);
};
extern LlmGuard llmGuard;
#endif
