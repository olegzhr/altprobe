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

#include "trace_delivery.h"
#include "trace_config.h"
#include "http_io.h"
#include "base64.h"
#include "bounded_json.h"
#include <openssl/sha.h>
#include <filesystem>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <thread>
#include <random>
#include <map>

std::string traceDigest(const std::string& text) {
    unsigned char bytes[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(), bytes);
    const char* hex = "0123456789abcdef"; std::string out;
    for (auto b : bytes) { out += hex[b >> 4]; out += hex[b & 15]; }
    return out;
}
namespace {
void report(const char* s) { CObject::SysLog(const_cast<char*>(s)); }
bool validId(const std::string& id) { return id.size() == 64 && id.find_first_not_of("0123456789abcdef") == std::string::npos; }
std::string traceIndex(const std::string& body) {
    Json document;
    if (!parseBoundedJson(body,document,33554432,1048576)) throw std::runtime_error("invalid trace document");
    const Json* spans = document.get("resourceSpans");
    if (spans && !spans->children.empty()) spans = spans->children.front().second.get("scopeSpans");
    if (spans && !spans->children.empty()) spans = spans->children.front().second.get("spans");
    const Json* time = spans && !spans->children.empty() ? spans->children.front().second.get("startTimeUnixNano") : nullptr;
    if (!time || (time->kind != 's' && time->kind != 'd') || time->text.empty() || time->text.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("missing span time");
    time_t seconds = std::stoull(time->text) / 1000000000;
    std::tm utc{}; if (!gmtime_r(&seconds,&utc)) throw std::runtime_error("invalid span time");
    char date[11]; if (!strftime(date,sizeof(date),"%Y-%m-%d",&utc)) throw std::runtime_error("invalid span date");
    return std::string("otel-v1-traces-") + (CObject::project_id.empty() ? "" : CObject::project_id+"-") + date;
}

class DiskSpool {
    int directory = -1;
    std::mutex mutex;
    std::vector<std::string> files() {
        std::vector<std::string> result;
        // A fresh open file description is needed; dup shares the directory offset.
        int fd = openat(directory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        DIR* d = fd < 0 ? nullptr : fdopendir(fd);
        if (!d) { if (fd >= 0) close(fd); throw std::runtime_error("read spool"); }
        while (auto e = readdir(d)) result.push_back(e->d_name);
        closedir(d); return result;
    }
public:
    ~DiskSpool() { if (directory >= 0) close(directory); }
    void openDirectory(const std::string& path) {
        if (directory >= 0) { close(directory); directory = -1; }
        if (std::filesystem::create_directories(path) && chmod(path.c_str(),0700)) throw std::runtime_error("protect spool");
        directory = ::open(path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        struct stat s{};
        if (directory < 0 || fstat(directory,&s) || s.st_uid != geteuid() || (s.st_mode & 0077)) throw std::runtime_error("private spool required");
        for (const auto& name : files()) if (name.size() == 68 && name.substr(64) == ".tmp" && validId(name.substr(0,64))) unlinkat(directory,name.c_str(),0);
        fsync(directory);
    }
    bool put(const std::string& body) {
        if (body.empty() || body.size() > 33554432) return false;
        std::lock_guard<std::mutex> lock(mutex);
        if (directory < 0) return false;
        auto id = traceDigest(body); auto name = id + ".json"; auto temp = id + ".tmp";
        struct stat existing{};
        if (!fstatat(directory,name.c_str(),&existing,AT_SYMLINK_NOFOLLOW))
            return S_ISREG(existing.st_mode) && existing.st_uid == geteuid() && !(existing.st_mode & 0077);
        size_t count = 0; uint64_t bytes = 0;
        for (const auto& f : files()) {
            if (f == "." || f == "..") continue;
            struct stat s{};
            if (fstatat(directory,f.c_str(),&s,AT_SYMLINK_NOFOLLOW) || !S_ISREG(s.st_mode)) return false;
            ++count; bytes += s.st_size;
        }
        if (count >= static_cast<size_t>(traceConfig().max_pending) || bytes + body.size() > traceConfig().max_spool_bytes) return false;
        int fd = openat(directory,temp.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (fd < 0) return false;
        size_t offset = 0;
        while (offset < body.size()) {
            auto n = write(fd,body.data()+offset,body.size()-offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            offset += n;
        }
        bool okay = offset == body.size() && !fsync(fd); close(fd);
        if (!okay || renameat(directory,temp.c_str(),directory,name.c_str())) { unlinkat(directory,temp.c_str(),0); return false; }
        return fsync(directory) == 0;
    }
    std::vector<std::string> ids() {
        std::lock_guard<std::mutex> lock(mutex); std::vector<std::string> out;
        for (const auto& name : files()) if (name.size() == 69 && name.substr(64) == ".json" && validId(name.substr(0,64))) out.push_back(name.substr(0,64));
        std::sort(out.begin(),out.end()); return out;
    }
    bool get(const std::string& id, std::string& body) {
        if (!validId(id)) return false;
        std::lock_guard<std::mutex> lock(mutex);
        int fd = openat(directory,(id+".json").c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        struct stat s{};
        bool okay = fd >= 0 && !fstat(fd,&s) && S_ISREG(s.st_mode) && s.st_uid == geteuid() && !(s.st_mode & 0077) && s.st_size > 0 && s.st_size <= 33554432;
        if (okay) {
            body.resize(s.st_size); size_t offset = 0;
            while (offset < body.size()) {
                auto n = read(fd,&body[offset],body.size()-offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                offset += n;
            }
            okay = offset == body.size() && traceDigest(body) == id;
        }
        if (fd >= 0) close(fd);
        return okay;
    }
    bool finish(const std::string& id, bool reject = false) {
        if (!validId(id)) return false;
        std::lock_guard<std::mutex> lock(mutex);
        int result = reject ? renameat(directory,(id+".json").c_str(),directory,(id+".rejected").c_str()) : unlinkat(directory,(id+".json").c_str(),0);
        return result == 0 && fsync(directory) == 0;
    }
};
struct Endpoint {
    bool https;
    std::string host,port,target;
    explicit Endpoint(std::string url) {
        https = url.rfind("https://",0) == 0;
        if (!https && url.rfind("http://",0) != 0) throw std::runtime_error("invalid trace URL");
        url.erase(0,https ? 8 : 7);
        if (url.find_first_of("?#@\\\r\n ") != std::string::npos) throw std::runtime_error("invalid trace URL");
        auto slash = url.find('/'); auto authority = url.substr(0,slash);
        target = slash == std::string::npos ? "" : url.substr(slash);
        while (!target.empty() && target.back() == '/') target.pop_back();
        port = https ? "443" : "80";
        if (authority.empty()) throw std::runtime_error("missing host");
        if (authority[0] == '[') {
            auto end = authority.find(']'); if (end == std::string::npos) throw std::runtime_error("invalid IPv6");
            host = authority.substr(1,end-1);
            if (end+1 < authority.size()) { if (authority[end+1] != ':') throw std::runtime_error("invalid port"); port = authority.substr(end+2); }
        } else {
            auto colon = authority.find(':'); host = authority.substr(0,colon);
            if (colon != std::string::npos) port = authority.substr(colon+1);
        }
        if (host.empty() || port.empty() || port.size()>5 || port.find_first_not_of("0123456789") != std::string::npos || std::stoi(port)<1 || std::stoi(port)>65535) throw std::runtime_error("invalid trace endpoint");
    }
};
}
struct TraceDelivery::Impl {
    enum class Destination { Alertflex, OpenSearch, Splunk, Graylog };
    DiskSpool af,os,splunk,graylog,input;
    std::atomic<bool> opened{false};
    std::atomic<bool> failed{false};
    void deliver(DiskSpool& queue, Destination destination, TraceDelivery& owner) {
        struct Retry { unsigned attempts = 0; std::chrono::steady_clock::time_point due{}; };
        std::map<std::string,Retry> retries;
        std::mt19937 random(std::random_device{}());
        Sinks sink;
        while (opened && owner.source_status) {
            for (const auto& id : queue.ids()) {
                if (!opened || !owner.source_status) break;
                auto& retry = retries[id];
                if (std::chrono::steady_clock::now() < retry.due) continue;
                std::string body;
                if (!queue.get(id,body)) { queue.finish(id,true); retries.erase(id); report("[Trace] invalid spool record quarantined"); continue; }
                bool accepted = false, permanent = false; unsigned delay = 0;
                try {
                    const auto stopping = [&] { return !opened || !owner.source_status; };
                    unsigned status = 0;
                    if (destination == Destination::Splunk) {
                        accepted = sink.sendTraceToSplunk(body, &status, stopping);
                    } else if (destination == Destination::Graylog) {
                        accepted = sink.sendTraceToGraylog(body, &status, stopping);
                    } else if (destination == Destination::Alertflex) {
                        Endpoint e(CObject::af_url);
                        e.target += "/traces/" + CObject::asset_name;
                        const auto auth = "Bearer " + CObject::af_key;
                        auto response = bounded_http::request(e.https,e.host,e.port,e.target,"POST",body,auth,
                            {{"Idempotency-Key",id}},"application/json",std::chrono::milliseconds(traceConfig().timeout_ms),
                            [&] { return !opened || !owner.source_status; },65536,
                            CObject::af_tls_verify,CObject::af_tls_ca_file);
                        status = response.result_int();
                        accepted = status >= 200 && status < 300;
                        if (accepted) {
                            Json ack;
                            accepted = parseBoundedJson(response.body(),ack,65536,128) && (ack.string("status") == "stored" || ack.string("status") == "accepted" || ack.string("status") == "duplicate");
                            if (ack.string("status") == "ignored") permanent = true;
                        }
                        auto after = std::string(response[boost::beast::http::field::retry_after]);
                        if (!after.empty() && after.size() <= 6 && after.find_first_not_of("0123456789") == std::string::npos) delay = std::min(3600u,static_cast<unsigned>(std::stoul(after)));
                    } else {
                        Endpoint e(CObject::os_url);
                        std::string encoded; Base64::Encode(CObject::os_user+":"+CObject::os_pwd,&encoded);
                        const auto auth = "Basic " + encoded;
                        // The OpenSearch ingest pipeline (altprobe-otel-spans)
                        // flattens OTLP into span.* documents, so the raw request
                        // is stored as one document and transformed server-side.
                        auto response = bounded_http::request(e.https,e.host,e.port,"/"+traceIndex(body)+"/_doc/"+id,"PUT",body,auth,
                            {{"Idempotency-Key",id}},"application/json",std::chrono::milliseconds(traceConfig().timeout_ms),
                            [&] { return !opened || !owner.source_status; },65536,
                            CObject::os_tls_verify,CObject::os_tls_ca_file);
                        status = response.result_int();
                        accepted = status >= 200 && status < 300;
                    }
                    permanent = permanent || (status >= 300 && status < 500 && status != 408 && status != 429 && status != 404 && status != 405);
                } catch (...) { /* network/TLS/deadline: retain exact payload */ }
                if ((accepted || permanent) && queue.finish(id,permanent)) {
                    retries.erase(id);
                    if (permanent) report("[Trace] permanent delivery error; payload retained as .rejected");
                } else {
                    retry.attempts = std::min(9u,retry.attempts+1);
                    delay = std::max(delay,std::min(300u,1u << (retry.attempts-1)));
                    retry.due = std::chrono::steady_clock::now()+std::chrono::milliseconds(delay*1000+random()%251);
                }
            }
            owner.WaitForStop(std::chrono::milliseconds(250));
        }
    }
};
TraceDelivery traceDelivery;
TraceDelivery::TraceDelivery() : impl_(new Impl) {}
TraceDelivery::~TraceDelivery() { Close(); }
bool TraceDelivery::Open() {
    try {
        const auto& c = traceConfig();
        if (!af_enable && !os_enable && !splunk_enable && !graylog_enable && c.mode != "external") { RequestStop(); return false; }
        if (std::filesystem::create_directories(c.spool_dir) && chmod(c.spool_dir.c_str(),0700)) throw std::runtime_error("protect spool");
        // Bind durable records to their configured tenant, asset and destinations.
        auto scope = traceDigest(project_id+"\n"+asset_name+"\n"+af_url+"\n"+os_url);
        auto base = c.spool_dir+"/"+scope;
        if (std::filesystem::create_directories(base) && chmod(base.c_str(),0700)) throw std::runtime_error("protect scope");
        impl_->af.openDirectory(base+"/alertflex"); impl_->os.openDirectory(base+"/opensearch"); impl_->input.openDirectory(base+"/incoming");
        if (splunk_enable && splunk_otel)
            impl_->splunk.openDirectory(base + "/splunk-" + traceDigest(splunk_url + "\n" + splunk_index));
        if (graylog_enable && graylog_otel)
            impl_->graylog.openDirectory(base + "/graylog-" + traceDigest(graylog_url));
        source_status = true; impl_->opened = true; return true;
    } catch (...) { report("[Trace] cannot initialize private durable spool"); RequestStop(); return false; }
}
bool TraceDelivery::ready() const { return impl_->opened; }
bool TraceDelivery::HasFailed() const { return impl_->failed; }
bool TraceDelivery::alertflex(const std::string& body) { try { return !af_enable || (ready() && impl_->af.put(body)); } catch (...) { return false; } }
bool TraceDelivery::opensearch(const std::string& body) { try { return !os_enable || !traceConfig().os_otel || (ready() && impl_->os.put(body)); } catch (...) { return false; } }
bool TraceDelivery::splunk(const std::string& body) { try { return !splunk_enable || !splunk_otel || (ready() && impl_->splunk.put(body)); } catch (...) { return false; } }
bool TraceDelivery::graylog(const std::string& body) { try { return !graylog_enable || !graylog_otel || (ready() && impl_->graylog.put(body)); } catch (...) { return false; } }
bool TraceDelivery::stageSinks(const std::string& body, size_t& next) {
    using Stage = bool (TraceDelivery::*)(const std::string&);
    static constexpr Stage sinks[] = {&TraceDelivery::opensearch, &TraceDelivery::splunk, &TraceDelivery::graylog};
    for (; next < std::size(sinks); ++next)
        if (!(this->*sinks[next])(body)) return false;
    return true;
}
bool TraceDelivery::incoming(const std::string& body) { try { return ready() && impl_->input.put(body); } catch (...) { return false; } }
std::vector<std::string> TraceDelivery::incomingIds() { return ready() ? impl_->input.ids() : std::vector<std::string>{}; }
bool TraceDelivery::readIncoming(const std::string& id,std::string& body) { return ready() && impl_->input.get(id,body); }
bool TraceDelivery::finishIncoming(const std::string& id) { return ready() && impl_->input.finish(id); }
bool TraceDelivery::Go() {
    using Destination = Impl::Destination;
    std::vector<std::thread> workers;
    auto start = [&](DiskSpool& queue, Destination destination) {
        workers.emplace_back([this, spool = &queue, destination] {
            try { impl_->deliver(*spool,destination,*this); }
            catch (...) { impl_->failed = true; impl_->opened = false; RequestStop(); report("[Trace] delivery worker failed; durable records retained"); }
        });
    };
    try {
        if (af_enable) start(impl_->af, Destination::Alertflex);
        if (os_enable) start(impl_->os, Destination::OpenSearch);
        if (splunk_enable && splunk_otel) start(impl_->splunk, Destination::Splunk);
        if (graylog_enable && graylog_otel) start(impl_->graylog, Destination::Graylog);
        while (source_status) WaitForStop(std::chrono::milliseconds(250));
    } catch (...) { impl_->failed = true; impl_->opened = false; RequestStop(); }
    for (auto& worker : workers) worker.join();
    return false;
}
void TraceDelivery::Close() { impl_->opened = false; RequestStop(); }
