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

#include "ids_source.h"
#include "detection.h"
#include <sys/stat.h>
#include <cctype>

namespace {
// Suricata, OpenShell and other JSONL sensors share the same transport; each derives its
// own SOURCES_<NAME>_REDIS / SOURCES_<NAME>_LOG keys from the source name.
std::string upperName(const std::string& value) {
    std::string result = value;
    for (auto& c : result) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return result;
}
}

IdsSource::IdsSource(const std::string& name) : Source(name + "_redis", ""), name_(name) {
    env_key = "SOURCES_" + upperName(name) + "_REDIS";
}
IdsSource::~IdsSource() {
    if (file_) fclose(file_);
    if (c) redisFree(c);
}
bool IdsSource::GetConfig(int mode) {
    if (!Source::GetConfig(mode)) return false;
    if (mode == 2) {
        const std::string key = "SOURCES_" + upperName(name_) + "_LOG";
        const char* value = getenv(key.c_str());
        log_path_ = value ? value : "";
        const char* id = getenv(("SOURCES_" + upperName(name_) + "_CONSUMER_ID").c_str());
        const char* name = getenv(("SOURCES_" + upperName(name_) + "_CONSUMER_NAME").c_str());
        consumer_id_ = id ? id : "";
        consumer_name_ = name ? name : "";
    } else {
        YamlConfig cfg;
        log_path_ = cfg.getString("sources", name_ + "_log");
        consumer_id_ = cfg.getString("sources", name_ + "_consumer_id");
        consumer_name_ = cfg.getString("sources", name_ + "_consumer_name");
    }
    source_status = !log_path_.empty() || redis_status;
    return true;
}
bool IdsSource::connectRedis() {
    if (c) { redisFree(c); c = nullptr; }
    timeval timeout{0, 250000};
    c = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
    if (!c || c->err || redisSetTimeout(c, timeout) != REDIS_OK || !InitializeRedisSession()) {
        if (c) redisFree(c);
        c = nullptr; retry_at_ = eventTimeMillis(0) + 1000;
        return false;
    }
    return true;
}
bool IdsSource::Open() {
    if (!source_status) return false;
    if (!log_path_.empty()) {
        file_ = fopen(log_path_.c_str(), "r");
        if (!file_) { source_status = false; return false; }
        fseeko(file_, 0, SEEK_END); // live tail; explicit replay uses Redis
    } else connectRedis(); // transient outages retry in the worker
    return true;
}
bool IdsSource::readFile(std::string& line) {
    if (!file_) return false;
    char buffer[8192];
    if (fgets(buffer, sizeof(buffer), file_)) {
        const size_t count = strlen(buffer);
        if (!oversized_) pending_.append(buffer, count);
        if (pending_.size() > 262144) {
            pending_.clear(); oversized_ = true;
        }
        if (count && buffer[count - 1] == '\n') {
            bool complete = !oversized_;
            line.swap(pending_); pending_.clear(); oversized_ = false;
            return complete;
        }
        return false;
    }
    clearerr(file_);
    struct stat current{}, opened{};
    if (stat(log_path_.c_str(), &current) == 0 && fstat(fileno(file_), &opened) == 0 &&
        (current.st_ino != opened.st_ino || current.st_dev != opened.st_dev || current.st_size < ftello(file_))) {
        FILE* replacement = fopen(log_path_.c_str(), "r");
        if (replacement) {
            fclose(file_); file_ = replacement; pending_.clear(); oversized_ = false;
        }
    }
    return false;
}
bool IdsSource::Go() {
    if (!source_status) return false;
    std::string line;
    if (file_) {
        if (readFile(line)) processLine(line);
        else WaitForStop(std::chrono::milliseconds(10));
    } else {
        if (!c && eventTimeMillis(0) >= retry_at_) connectRedis();
        if (c) {
            // Source::GetConfig stores "lpop <key>". Use a binary argument so
            // spaces and percent signs in a configured key stay literal.
            const auto key = redis_key.substr(5);
            redisReply* result = static_cast<redisReply*>(redisCommand(c, "LPOP %b", key.data(), key.size()));
            if (!result) { redisFree(c); c = nullptr; retry_at_ = eventTimeMillis(0) + 1000; }
            else {
                if (result->type == REDIS_REPLY_STRING && result->len <= 262144)
                    line.assign(result->str, result->len);
                freeReplyObject(result);
            }
        }
        if (!line.empty()) {
            processLine(line);
        } else WaitForStop(std::chrono::milliseconds(50));
    }
    return source_status;
}
