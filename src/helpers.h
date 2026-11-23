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

#ifndef HELPERS_H
#define	HELPERS_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <fstream>
#include <string>
#include <unordered_set>

#include "main.h"
#include "detection.h"

using namespace std;

unsigned int getBufferSize(const char* source);
bool isValidJSON(const std::string& str);
std::string normalizeHexEscapes(const std::string& input);
std::string fixRawJsonString(const std::string& input);
std::string escapeJsonString(const std::string& s);
bool isInternalCollectorDest(const std::string& url);
bool isInternalCollectorDest(const std::string& url,
                             const std::string& dest_host,
                             unsigned int dest_port);
bool isValidIp(const std::string& ip);
uint64_t parseTimeToMillis(const std::string& iso_time);
std::string buildApiGuardActivityJson(const Event& e,
                                      const std::string& uid,
                                      const std::string& source_name,
                                      long logged_time);
std::string buildApiGuardExplanationJson(const GuardMatch& match);
std::string buildLlmGuardExplanationJson(const LlmGuardMatch& match);
std::string buildMcpDriftsJson(const std::vector<McpDrift>& drifts);
bool isApiGuardThreat(const Event& event);
bool isApiGuardActivity(const Event& event);

#endif	/* HELPERS_H */


