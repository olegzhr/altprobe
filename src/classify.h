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

#ifndef CLASSIFY_H
#define CLASSIFY_H

#include <string>
#include "detection.h"

void loadApiGuardPatterns(const std::string& path);

SignalType classifyHttpMcpSignal(
    const std::string& method,
    const std::string& url,
    const std::string& headers,
    const std::string& body,
    const std::string& response,
    GuardMatch* detail = nullptr);

SignalType classifyRestSignal(
    const std::string& method,
    const std::string& url,
    const std::string& headers,
    const std::string& body,
    const std::string& response,
    GuardMatch* detail = nullptr);

#endif /* CLASSIFY_H */

