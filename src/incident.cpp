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

#include "incident.h"
#include "http_io.h"
#include "bounded_json.h"
#include <filesystem>
#include <random>
#include <regex>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <cerrno>

namespace {
constexpr size_t maxBody = 262144;
bool safeId(const std::string& id) {
    static const std::regex pattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    return std::regex_match(id, pattern);
}
void report(const char* message) { CObject::SysLog(const_cast<char*>(message)); }
bool safeText(const std::string& s) {
    return std::none_of(s.begin(), s.end(), [](unsigned char c) { return c <= 32 || c == 127; });
}
}

Incident::~Incident() { if (directory_ >= 0) ::close(directory_); }

bool Incident::Open() {
    incident_ready = false;
    opened_ = false;
    if (!incident_enabled) { source_status = false; return false; }
    try {
        project_ = project_id; token_ = af_key;
        timeout_ = incident_timeout_ms; capacity_ = incident_max_pending;
        static const std::regex projectPattern("[A-Za-z0-9][A-Za-z0-9_-]{0,127}");
        if (!std::regex_match(project_, projectPattern) || token_.empty() || !safeText(token_) ||
            timeout_ < 100 || timeout_ > 60000 || incident_max_pending < 1 || incident_max_pending > 4096)
            throw std::runtime_error("invalid incident configuration");
        std::string url = incident_url.empty() ? af_url : incident_url;
        if (!safeText(url) || url.find_first_of("?#\\") != std::string::npos)
            throw std::runtime_error("invalid incident URL");
        if (url.rfind("https://", 0) == 0) { https_ = true; url.erase(0, 8); }
        else if (url.rfind("http://", 0) == 0 && incident_allow_http) { https_ = false; url.erase(0, 7); }
        else throw std::runtime_error("HTTPS required (HTTP only with allow_http)");
        size_t slash = url.find('/');
        authority_ = url.substr(0, slash);
        std::string base = slash == std::string::npos ? "" : url.substr(slash);
        if (authority_.empty() || authority_.find('@') != std::string::npos)
            throw std::runtime_error("invalid incident authority");
        port_ = https_ ? "443" : "80";
        if (authority_[0] == '[') {
            size_t bracket = authority_.find(']');
            if (bracket == std::string::npos) throw std::runtime_error("invalid IPv6 authority");
            host_ = authority_.substr(1, bracket - 1);
            boost::asio::ip::make_address_v6(host_);
            if (bracket + 1 < authority_.size()) {
                if (authority_[bracket + 1] != ':') throw std::runtime_error("invalid authority");
                port_ = authority_.substr(bracket + 2);
            }
        } else {
            size_t colon = authority_.find(':');
            host_ = authority_.substr(0, colon);
            if (colon != std::string::npos) port_ = authority_.substr(colon + 1);
            static const std::regex hostPattern("[A-Za-z0-9.-]+");
            if (!std::regex_match(host_, hostPattern)) throw std::runtime_error("invalid host");
        }
        if (port_.empty() || port_.size() > 5 || port_.find_first_not_of("0123456789") != std::string::npos ||
            std::stoi(port_) < 1 || std::stoi(port_) > 65535) throw std::runtime_error("invalid port");
        while (!base.empty() && base.back() == '/') base.pop_back();
        target_ = base + "/projects/" + project_ + "/incidents";
        if (incident_spool_dir.empty()) throw std::runtime_error("spool_dir required");
        bool created = std::filesystem::create_directories(incident_spool_dir);
        if (created && ::chmod(incident_spool_dir.c_str(), 0700)) throw std::runtime_error("cannot protect spool");
        if (directory_ >= 0) { ::close(directory_); directory_ = -1; }
        directory_ = ::open(incident_spool_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat status{};
        if (directory_ < 0 || fstat(directory_, &status) || status.st_uid != geteuid() || (status.st_mode & 0077))
            throw std::runtime_error("spool must be owned by service user, private, and not a symlink");
        pending_.clear(); ids_.clear(); records_ = 0; unstaged_.reset();
        load();
        source_status = true; opened_ = true; incident_ready = true;
        report("[Incident] Alertflex incident delivery enabled");
        return true;
    } catch (const std::exception&) {
        // No endpoint, token or incident content in diagnostics.
        report("[Incident] disabled: invalid endpoint, credentials, project, limits or private spool");
        source_status = false;
        return false;
    }
}

void Incident::Close() { incident_ready = false; opened_ = false; RequestStop(); }

bool Incident::valid(const IncidentEnvelope& incident) const {
    if (!safeId(incident.id) || incident.body.size() > maxBody) return false;
    Json doc;
    if (!parseBoundedJson(incident.body, doc, maxBody, 32768) || doc.kind != 'o' ||
        doc.string("incident_id") != incident.id || doc.string("schema_version") != "1.0" ||
        doc.string("project_id") != project_) return false;
    auto finding = doc.get("finding"), probe = doc.get("probe");
    if (!finding || finding->kind != 'o' || !probe || probe->kind != 'o') return false;
    auto cls = finding->get("class_uid"), severity = finding->get("severity_id");
    return cls && cls->kind == 'd' && cls->text == "6003" && severity && severity->kind == 'd' && (severity->text == "3" || severity->text == "4");
}

void Incident::load() {
    DIR* dir = fdopendir(dup(directory_));
    if (!dir) throw std::runtime_error("cannot read spool");
    std::vector<std::string> files;
    while (auto entry = readdir(dir)) {
        std::string name = entry->d_name;
        // A crash before atomic rename may leave an incomplete temp file.
        if (name.size() == 40 && name.substr(36) == ".tmp" && safeId(name.substr(0, 36)))
            unlinkat(directory_, name.c_str(), 0);
        if (name.size() == 41 && name.substr(36) == ".json") files.push_back(name);
        if (name.size() == 45 && name.substr(36) == ".rejected") ids_.insert(name.substr(0, 36));
        if ((name.size() == 45 && name.substr(36) == ".rejected") || (name.size() == 41 && name.substr(36) == ".json"))
            ++records_;
        if (records_ > capacity_) { closedir(dir); throw std::runtime_error("spool exceeds capacity"); }
    }
    closedir(dir);
    for (const auto& name : files) {
        IncidentEnvelope incident{name.substr(0, 36), ""};
        int fd = openat(directory_, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat status{};
        bool okay = fd >= 0 && !fstat(fd, &status) && S_ISREG(status.st_mode) && status.st_uid == geteuid() &&
            !(status.st_mode & 0077) && status.st_size > 0 && status.st_size <= static_cast<off_t>(maxBody);
        if (okay) {
            incident.body.resize(status.st_size);
            size_t offset = 0;
            while (offset < incident.body.size()) {
                ssize_t n = read(fd, &incident.body[offset], incident.body.size() - offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { okay = false; break; } offset += n;
            }
        }
        if (fd >= 0) ::close(fd);
        if (okay && valid(incident)) { pending_.push_back({incident}); ids_.insert(incident.id); }
        else {
            std::string rejected = incident.id + ".rejected";
            if (renameat(directory_, name.c_str(), directory_, rejected.c_str()))
                throw std::runtime_error("cannot quarantine invalid spool record");
            report("[Incident] invalid or different-project spool record quarantined");
        }
    }
    fsync(directory_);
}

// Write and sync a private temporary file, then publish it atomically. Recovery
// reads only complete .json records; a partial write must never look deliverable.
bool Incident::persist(const IncidentEnvelope& incident) {
    const std::string name = incident.id + ".json", temp = incident.id + ".tmp";
    int fd = openat(directory_, temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t offset = 0;
    while (offset < incident.body.size()) {
        ssize_t n = write(fd, incident.body.data() + offset, incident.body.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        offset += n;
    }
    bool okay = offset == incident.body.size() && fsync(fd) == 0;
    ::close(fd);
    if (!okay || renameat(directory_, temp.c_str(), directory_, name.c_str())) { unlinkat(directory_, temp.c_str(), 0); return false; }
    return fsync(directory_) == 0;
}

// HTTP success alone is insufficient: the acknowledgement must name this UUID.
// Retry state uses a monotonic clock so wall-clock adjustments cannot skip retries.
void Incident::deliver(Pending& pending, bool& finished) {
    bool accepted = false, permanent = false;
    unsigned httpStatus = 0;
    unsigned retryAfter = 0;
    try {
        auto res = bounded_http::request(https_, host_, port_, target_, "POST", pending.incident.body,
            "Bearer " + token_, {{"Idempotency-Key", pending.incident.id}, {"Host", authority_}}, "application/json",
            std::chrono::milliseconds(timeout_), [&] { return !opened_ || !source_status; }, 65536, af_tls_verify, af_tls_ca_file);
        unsigned status = res.result_int();
        httpStatus = status;
        if (status == 200 || status == 202) {
            Json ack;
            accepted = parseBoundedJson(res.body(), ack, 65536, 128) && ack.kind == 'o' &&
                ack.string("incident_id") == pending.incident.id &&
                (ack.string("status") == "accepted" || ack.string("status") == "duplicate");
        } else {
            // 404/405 during a controller deploy means the route is not up
            // yet, not that the incident is permanently invalid. Retry it,
            // but bounded so a genuinely wrong endpoint cannot fill the spool.
            const bool deploy_transient = status == 404 || status == 405;
            permanent = status >= 300 && status < 500 && status != 408 && status != 429 &&
                (!deploy_transient || pending.attempts >= 20);
        }
        auto retry = std::string(res[boost::beast::http::field::retry_after]);
        if (!retry.empty() && retry.size() <= 6 && retry.find_first_not_of("0123456789") == std::string::npos)
            retryAfter = std::min(3600u, static_cast<unsigned>(std::stoul(retry)));
    } catch (const std::exception&) { /* network/TLS/deadline: retain record */ }
    const std::string file = pending.incident.id + ".json";
    if (accepted && !unlinkat(directory_, file.c_str(), 0)) {
        fsync(directory_); --records_; ids_.erase(pending.incident.id); finished = true;
        report(("[Incident] incident=" + pending.incident.id + " acknowledged by Alertflex").c_str());
    } else if (permanent) {
        const std::string rejected = pending.incident.id + ".rejected";
        if (!renameat(directory_, file.c_str(), directory_, rejected.c_str())) {
            fsync(directory_); finished = true;
            report(("[Incident] incident=" + pending.incident.id + " HTTP=" + std::to_string(httpStatus) + " rejected; retained as .rejected for operator review").c_str());
        }
    }
    if (!finished) {
        pending.attempts = std::min(20u, pending.attempts + 1);
        static thread_local std::mt19937 random(std::random_device{}());
        unsigned delay = std::min(300u, 1u << std::min(8u, pending.attempts - 1));
        unsigned jitter = std::uniform_int_distribution<unsigned>(0, delay * 250)(random);
        pending.due = std::chrono::steady_clock::now() + std::chrono::seconds(std::max(delay, retryAfter)) + std::chrono::milliseconds(jitter);
        report(("[Incident] incident=" + pending.incident.id + " HTTP=" + std::to_string(httpStatus) + " attempt=" + std::to_string(pending.attempts) + " not acknowledged; retained for retry").c_str());
    }
}

bool Incident::Go() {
    if (!opened_ || !source_status || !incident_enabled) { incident_ready = false; return false; }
    auto warning = [&](const char* message) {
        auto now = std::chrono::steady_clock::now();
        if (now - last_warning_ >= std::chrono::seconds(30)) { report(message); last_warning_ = now; }
    };
    if (records_ >= capacity_ && q_finding_incident.read_available())
        warning("[Incident] spool capacity reached; ingestion paused, operator review may be required");
    // Persist a bounded batch before sending. Stop popping on full disk or write failure.
    for (unsigned i = 0; i < 16 && records_ < capacity_; ++i) {
        if (!unstaged_) {
            IncidentEnvelope incident;
            if (!q_finding_incident.pop(incident)) break;
            unstaged_ = std::move(incident);
        }
        if (!valid(*unstaged_)) { report("[Incident] invalid incident discarded"); unstaged_.reset(); continue; }
        if (ids_.count(unstaged_->id)) { unstaged_.reset(); continue; }
        if (!persist(*unstaged_)) { warning("[Incident] spool write failed; ingestion paused"); break; }
        ids_.insert(unstaged_->id); pending_.push_back({*unstaged_}); ++records_; unstaged_.reset();
    }
    // One attempt per iteration; due-time rotation prevents a bad record starving others.
    size_t count = pending_.size();
    while (count-- && opened_ && source_status) {
        Pending pending = std::move(pending_.front()); pending_.pop_front();
        if (pending.due > std::chrono::steady_clock::now()) { pending_.push_back(std::move(pending)); continue; }
        bool finished = false;
        deliver(pending, finished);
        if (!finished) pending_.push_back(std::move(pending));
        break;
    }
    WaitForStop(std::chrono::milliseconds(50));
    return opened_ && source_status;
}
