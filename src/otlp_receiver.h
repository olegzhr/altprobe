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

#ifndef ALTPROBE_OTLP_RECEIVER_H
#define ALTPROBE_OTLP_RECEIVER_H
#include "source.h"
#include <memory>
class OtlpReceiver : public Source {
public:
    OtlpReceiver();
    ~OtlpReceiver() override;
    bool Open() override;
    bool Go() override;
    void Close() override;
    bool HasFailed() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
#endif
