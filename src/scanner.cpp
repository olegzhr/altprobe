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

#include "scanner.h"

#include <fstream>
#include <sstream>
#include <map>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include <yaml-cpp/yaml.h>

// boost json
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace bpt = boost::property_tree;

#define SBOM_CONFIG_FILE "/etc/altprobe/sbom.yaml"

static string jsonEscape(const string& value) {
    string out;
    out.reserve(value.size() + 16);
    for (char c : value) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"': out.append("\\\""); break;
            case '\b': out.append("\\b"); break;
            case '\f': out.append("\\f"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out.append(buf);
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    return out;
}

static bool parseJsonDocument(const std::string& text, bpt::ptree& out) {
    try {
        std::stringstream ss(text);
        bpt::read_json(ss, out);
        return true;
    } catch (...) {
        return false;
    }
}

static std::string findingUid(const std::string& asset_name,
                              const std::string& service_name,
                              const std::string& cve_id,
                              const std::string& affected) {
    return asset_name + ":" + service_name + ":" + cve_id + ":" + affected;
}

bool Scanner::GetConfig(int mode) {

    if (!Source::GetConfig(mode)) return false;

    scan_interval = 0;
    scan_list.clear();

    string config_path = SBOM_CONFIG_FILE;

    try {
        if (mode == 2) {
            const char* env_val = getenv("ALTPROBE_SBOM_CONFIG");
            if (env_val && strlen(env_val) > 0) config_path = env_val;
        }

        const YAML::Node root = YAML::LoadFile(config_path);

        if (!root.IsDefined() || !root.IsMap()) {
            SysLog("scanner config error: cannot load sbom configuration file");
            source_status = false;
            return true;
        }

        const YAML::Node& scan_interval_node = root["scan_interval"];

        if (scan_interval_node.IsDefined() && scan_interval_node.IsScalar()) {
            scan_interval = scan_interval_node.as<int>(0);
        }

        if (scan_interval <= 0) {
            if (log_debug) printf("scanner.scan_interval: %d (module disabled)\n", scan_interval);
            source_status = false;
            return true;
        }

        scan_timeout_sec = root["scan_timeout_sec"] ? root["scan_timeout_sec"].as<int>() : 300;
        if (scan_timeout_sec < 1 || scan_timeout_sec > 3600)
            throw std::runtime_error("scan_timeout_sec must be in 1..3600");

        if (log_debug) printf("scanner.scan_interval: %d (minutes)\n", scan_interval);

        const YAML::Node& pipeline_node = root["pipeline"];
        if (pipeline_node.IsDefined() && pipeline_node.IsSequence()) {
            for (const auto& item_node : pipeline_node) {
                if (!item_node.IsMap()) continue;

                SbomScanItem item;
                const YAML::Node& service_name_node = item_node["service_name"];
                const YAML::Node& scan_command_node = item_node["scan_command"];
                const YAML::Node& scan_output_node = item_node["scan_output"];

                if (service_name_node.IsDefined() && service_name_node.IsScalar()) {
                    item.service_name = service_name_node.as<string>();
                }
                if (scan_command_node.IsDefined() && scan_command_node.IsScalar()) {
                    item.scan_command = scan_command_node.as<string>();
                }
                if (scan_output_node.IsDefined() && scan_output_node.IsScalar()) {
                    item.scan_output = scan_output_node.as<string>();
                }

                if (item.service_name.empty() || item.scan_command.empty() || item.scan_output.empty()) {
                    continue;
                }

                scan_list.push_back(item);

                if (log_debug) {
                    printf("scanner.pipeline.service_name: %s\n", (char*) item.service_name.c_str());
                    printf("scanner.pipeline.scan_command: %s\n", (char*) item.scan_command.c_str());
                    printf("scanner.pipeline.scan_output: %s\n", (char*) item.scan_output.c_str());
                }
            }
        }

        if (scan_list.empty()) {
            SysLog("scanner config warning: sbom pipeline is empty");
            source_status = false;
        }

    } catch (const std::exception& e) {
        string msg = "scanner config error: ";
        msg.append(e.what());
        SysLog((char*) msg.c_str());
        source_status = false;
        return true;
    }

    return true;
}

bool Scanner::Open() {

    if (!af_enable && !os_enable && !splunk_enable && !graylog_enable) {
        source_status = false;
    }

    if (source_status) {
        string msg = "[Scanner] SBOM scanner started, scan interval (minutes)=";
        msg.append(to_string(scan_interval));
        SysLog((char*) msg.c_str());
    }

    return source_status;
}

bool Scanner::Go() {

    // Run a full scan pass over all configured pipelines
    if (source_status) {
        for (const auto& item : scan_list) {
            if (!source_status) break;
            runScan(item);
        }
    }

    WaitForStop(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::minutes(scan_interval)));

    return source_status;
}

bool Scanner::runScanCommand(const std::string& command) {
    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes) != 0) return false;
    pid_t child = -1;
    char* args[] = {const_cast<char*>("sh"), const_cast<char*>("-c"), const_cast<char*>(command.c_str()), nullptr};
    const int error = posix_spawnattr_setpgroup(&attributes, 0) ||
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP) ||
        posix_spawn(&child, "/bin/sh", nullptr, &attributes, args, environ);
    posix_spawnattr_destroy(&attributes);
    if (error) return false;

    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::seconds(scan_timeout_sec);
    int status = 0;
    while (source_status && Clock::now() < deadline) {
        const auto result = waitpid(child, &status, WNOHANG);
        if (result == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (result < 0 && errno != EINTR) return false;
        WaitForStop(std::chrono::milliseconds(50));
    }

    SysLog(source_status ? "[Scanner] scan command timed out" : "[Scanner] scan command cancelled");
    // Signal the whole pipeline. Reap the leader after signalling to keep the group ID reserved.
    kill(-child, SIGTERM);
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    kill(-child, SIGKILL);
    const auto reap_deadline = Clock::now() + std::chrono::seconds(1);
    while (Clock::now() < reap_deadline) {
        const auto result = waitpid(child, &status, WNOHANG);
        if (result == child || (result < 0 && errno != EINTR)) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    // Avoid spawning further children while one is stuck in uninterruptible I/O.
    SysLog("[Scanner] child did not exit, scanner paused");
    RequestStop();
    return false;
}

bool Scanner::runScan(const SbomScanItem& item) {
    string msg = "[Scanner] scanning " + item.service_name;
    SysLog((char*) msg.c_str());

    try {
        if (!runScanCommand(item.scan_command)) {
            msg = "[Scanner] scan did not complete for " + item.service_name;
            SysLog((char*) msg.c_str());
            return false;
        }

        std::ifstream report(item.scan_output.c_str(), std::ios::binary);
        if (!report.is_open()) {
            msg = "[Scanner] cannot open sbom output: ";
            msg.append(item.scan_output);
            SysLog((char*) msg.c_str());
            return false;
        }

        std::stringstream ss;
        ss << report.rdbuf();
        report.close();

        std::string sbom_json = ss.str();
        if (sbom_json.empty()) {
            msg = "[Scanner] sbom output is empty: ";
            msg.append(item.scan_output);
            SysLog((char*) msg.c_str());
            return false;
        }

        bpt::ptree sbom_doc;
        if (!parseJsonDocument(sbom_json, sbom_doc)) {
            msg = "[Scanner] sbom output is not valid JSON: ";
            msg.append(item.scan_output);
            SysLog((char*) msg.c_str());
            return false;
        }

        // Publish findings to OpenSearch as OCSF 2002 when enabled. The whole
        // CycloneDX document (including the same vulnerabilities array) is then
        // pushed to Alertflex, which extracts both components and findings.
        reportVulnerabilityFindings(item.service_name, sbom_json);

        if (af_enable)
            return pushSbomToAF(item.service_name, sbom_json);

        return os_enable;

    } catch (const std::exception& e) {
        msg = "[Scanner] scan exception: ";
        msg.append(e.what());
        SysLog((char*) msg.c_str());
        return false;
    }
}

bool Scanner::pushSbomToAF(const std::string& service_name, const std::string& sbom_json) {

    if (!af_enable || af_url.empty() || af_key.empty()) {
        SysLog("[Scanner] Alertflex not configured");
        return false;
    }

    try {
        bool is_https = (af_url.find("https://") == 0);
        bool is_http = (af_url.find("http://") == 0);
        if (!is_https && !is_http) {
            SysLog("[Scanner] Alertflex URL must start with http:// or https://");
            return false;
        }

        std::string url = af_url.substr(is_https ? 8 : 7);

        size_t slash = url.find('/');
        std::string host_part = (slash != std::string::npos) ? url.substr(0, slash) : url;
        std::string base_path = (slash != std::string::npos) ? url.substr(slash) : "";

        if (!base_path.empty() && base_path.back() == '/') {
            base_path.pop_back();
        }

        std::string target = base_path + "/sbom/" + asset_name;

        std::string host, port;
        size_t colon = host_part.find(':');
        if (colon != std::string::npos) {
            host = host_part.substr(0, colon);
            port = host_part.substr(colon + 1);
        } else {
            host = host_part;
            port = is_https ? "443" : "80";
        }

        // The sbom_json value is already a valid JSON object/array (CycloneDX
        // document produced by trivy), so it is embedded into the payload
        // verbatim instead of being re-escaped as a string.
        std::string json =
            "{"
            "\"asset_name\":\"" + jsonEscape(asset_name) + "\","
            "\"service_name\":\"" + jsonEscape(service_name) + "\","
            "\"sbom\":" + sbom_json +
            "}";

        std::string auth = "Bearer " + af_key;

        return sk.sendHttpRequest(
            is_https,
            host,
            port,
            target,
            "POST",
            json,
            auth,
            {},
            "application/json", af_tls_verify, af_tls_ca_file
        );

    } catch (const std::exception& e) {
        string msg = "[Scanner] push exception: ";
        msg.append(e.what());
        SysLog((char*) msg.c_str());
        return false;
    }
}

static int ocsfSeverityId(const std::string& severity) {
    std::string s = severity;
    for (size_t i = 0; i < s.size(); i++) {
        s[i] = (char) std::toupper((unsigned char) s[i]);
    }

    if (s == "CRITICAL") return 5;
    if (s == "HIGH") return 4;
    if (s == "MEDIUM") return 3;
    if (s == "LOW") return 2;
    if (s == "INFO" || s == "INFORMATIONAL") return 1;
    return 0;
}

static std::string ocsfSeverityName(const std::string& severity) {
    std::string s = severity;
    for (size_t i = 0; i < s.size(); i++) {
        s[i] = (char) std::tolower((unsigned char) s[i]);
    }

    if (s == "critical") return "Critical";
    if (s == "high") return "High";
    if (s == "medium") return "Medium";
    if (s == "low") return "Low";
    if (s == "info" || s == "informational") return "Informational";
    return "Unknown";
}

static std::string ptreeSafeString(const bpt::ptree& node, const char* key) {
    try {
        const bpt::ptree& child = node.get_child(key);
        return child.data();
    } catch (...) {
        return "";
    }
}

void Scanner::reportVulnerabilityFindings(const std::string& service_name, const std::string& sbom_json) {

    if (!os_enable) return;

    try {
        std::stringstream ss(sbom_json);
        bpt::ptree root;
        bpt::read_json(ss, root);

        // Build a map of bom-ref -> component to resolve "affects" references
        std::map<std::string, std::string> ref_components;
        auto components_node = root.get_child_optional("components");
        if (components_node) {
            for (const auto& item : components_node.get()) {
                const bpt::ptree& comp = item.second;
                std::string bom_ref = ptreeSafeString(comp, "bom-ref");
                if (bom_ref.empty()) continue;

                std::string name = ptreeSafeString(comp, "name");
                std::string version = ptreeSafeString(comp, "version");
                std::string purl = ptreeSafeString(comp, "purl");

                std::string desc = name;
                if (!version.empty()) desc += "@" + version;
                if (!purl.empty()) desc += " " + purl;

                ref_components[bom_ref] = desc;
            }
        }

        // Parse vulnerabilities
        auto vuln_node = root.get_child_optional("vulnerabilities");
        if (!vuln_node) return;

        for (const auto& vuln_item : vuln_node.get()) {
            const bpt::ptree& vuln = vuln_item.second;

            std::string cve_id = ptreeSafeString(vuln, "id");
            if (cve_id.empty()) continue;

            std::string severity = "UNKNOWN";
            std::string affected = service_name;

            // Grab severity from the first rating (best-effort)
            auto ratings = vuln.get_child_optional("ratings");
            if (ratings) {
                for (const auto& rating_item : ratings.get()) {
                    const bpt::ptree& rating = rating_item.second;
                    std::string sev = ptreeSafeString(rating, "severity");
                    if (!sev.empty()) {
                        severity = sev;
                        break;
                    }
                }
            }

            // Resolve affected component
            auto affects = vuln.get_child_optional("affects");
            if (affects) {
                for (const auto& affects_item : affects.get()) {
                    const bpt::ptree& affect = affects_item.second;
                    std::string ref = ptreeSafeString(affect, "ref");
                    auto it = ref_components.find(ref);
                    if (it != ref_components.end()) {
                        affected = it->second;
                        break;
                    }
                }
            }

            std::string description = ptreeSafeString(vuln, "description");
            if (description.empty()) description = ptreeSafeString(vuln, "detail");

            auto now = std::chrono::system_clock::now();
            auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            std::string json;
            json.append("{ \"activity_id\": 1, \"category_uid\": 2, \"category_name\": \"Findings\"");
            json.append(",\"class_uid\": 2002, \"class_name\": \"Vulnerability Finding\"");
            json.append(", \"metadata\": { \"log_name\":\"altprobe_sbom\", \"log_provider\": \"Alertflex\", \"logged_time\": ");
            json.append(std::to_string(milliseconds));
            json.append(", \"uid\":\"");
            json.append(jsonEscape(findingUid(asset_name, service_name, cve_id, affected)));
            json.append("\"");
            json.append(", \"version\":\"1.8.0\", \"product\": { \"vendor_name\": \"Trivy\"} }");

            json.append(", \"severity_id\": ");
            json.append(std::to_string(ocsfSeverityId(severity)));
            json.append(", \"severity\": \"");
            json.append(ocsfSeverityName(severity));
            json.append("\"");

            json.append(", \"vulnerability\": { \"uid\": \"");
            json.append(jsonEscape(cve_id));
            json.append("\", \"title\": \"");
            json.append(jsonEscape(affected));
            json.append("\"");

            if (!description.empty()) {
                json.append(", \"desc\": \"");
                json.append(jsonEscape(description));
                json.append("\"");
            }

            json.append(" }, \"message\": \"Vulnerability ");
            json.append(jsonEscape(cve_id));
            json.append(" found in ");
            json.append(jsonEscape(affected));
            json.append("\", \"time\": ");
            json.append(std::to_string(milliseconds));
            json.append(", \"type_uid\": 200201 }");

            if (log_debug) {
                SysLog((char*) "Scanner OCSF Vulnerability Finding record:");
                SysLog((char*) json.c_str());
            }

            sk.sendOcsfToLogSinks(json, 2002, "indef", "scanner");
        }

    } catch (const std::exception& e) {
        string msg = "[Scanner] vulnerability report exception: ";
        msg.append(e.what());
        SysLog((char*) msg.c_str());
    }
}
