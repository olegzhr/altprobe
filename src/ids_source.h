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

#ifndef ALTPROBE_IDS_SOURCE_H
#define ALTPROBE_IDS_SOURCE_H
#include "source.h"

// Shared file/Redis transport for EVE/OpenShell. A dedicated worker
// owns the file and Redis handles; Close only signals it, avoiding close/read races.
class IdsSource : public Source {
    std::string name_, log_path_, pending_;
    std::string consumer_id_, consumer_name_;
    FILE* file_ = nullptr;
    bool oversized_ = false;
    long retry_at_ = 0;
    bool connectRedis();
    bool readFile(std::string& line);
protected:
    virtual bool processLine(const std::string& line) = 0;
    const std::string& consumerId() const { return consumer_id_; }
    const std::string& consumerName() const { return consumer_name_; }
public:
    explicit IdsSource(const std::string& name);
    ~IdsSource() override;
    bool GetConfig(int mode) override;
    bool Open() override;
    bool Go() override;
    void Close() override { RequestStop(); }
};
#endif
