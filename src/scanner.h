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

#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

#include "source.h"

using namespace std;

// One entry of the "pipeline" section from sbom.yaml. Each entry describes a
// separate SBOM scan (trivy command) whose CycloneDX output is pushed to the
// Alertflex inventory endpoint under a service name.
class SbomScanItem {
public:
    string service_name;
    string scan_command;
    string scan_output;

    void Reset() {
        service_name.clear();
        scan_command.clear();
        scan_output.clear();
    }
};

class Scanner : public Source {

public:

    int scan_interval;   // Scan interval in minutes, 0 disables the module
    vector<SbomScanItem> scan_list;

    Scanner() : Source() {
        scan_interval = 0;
    }

    virtual bool GetConfig(int mode);
    virtual bool Open();
    virtual bool Go();

private:

    int scan_timeout_sec = 300;
    bool runScanCommand(const std::string& command);
    bool runScan(const SbomScanItem& item);
    bool pushSbomToAF(const std::string& service_name, const std::string& sbom_json);
    void reportVulnerabilityFindings(const std::string& service_name, const std::string& sbom_json);
};

#endif /* SCANNER_H */
