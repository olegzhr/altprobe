/*
 *   Copyright 2021 Oleg Zharkov
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

#ifndef SUPP_H
#define	SUPP_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <fstream>
#include <string>
#include <unordered_set>

#include "main.h"

using namespace std;

int ValidDigit(char* ip_str);
int IsValidIp(string ip);
uint32_t IPToUInt(string ip);
bool IsIPInRange(string ip, string network, string mask);
unsigned int GetBufferSize(const char* source);
char* GetBody(char* source);
std::chrono::system_clock::time_point stringToTimestamp(const std::string& dateString);

#endif	/* SUPP_H */

