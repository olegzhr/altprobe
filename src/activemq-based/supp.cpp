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

#include "supp.h"

int ValidDigit(char* ip_str) {
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return 0;
    }
    return 1;
}
 
/* return -1 if IP string isn't valide, return 0 if IP string is private, return 1 if IP string is public */
int IsValidIp(string ip) {
    
    int i = 0;
    char* ptr;
    int n[4];
    char ip_tmp[32];
    
    memset(ip_tmp, 0, sizeof(ip_tmp));
    strncpy (ip_tmp, ip.c_str(), sizeof(ip_tmp));
    
    ptr = strtok(ip_tmp, DELIM);
    if (ptr == NULL) return -1;
    /* after parsing string, it must contain only digits */
    n[0] = atoi(ptr);
    /* check for valid IP */
    if (n[0] < 0 && n[0] > 255) return -1;
 
    for(i = 1; i< 4; i++) {
        
        ptr = strtok(NULL, DELIM);
        if (ptr == NULL) return -1;
        if (!ValidDigit(ptr)) return -1;
        n[i] = atoi(ptr);
        
        if (n[i] < 0 && n[i] > 255) return -1;
    }
 
    
    if((n[0] == 10 && n[1] >= 0 && n[1] <= 255 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255) 
        || (n[0] == 172 && n[1] >= 16 && n[1] <= 31 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255) 
        || (n[0] == 192 && n[1] == 168 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255) 
        || (n[0] == 169 && n[1] == 254 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255)
        || (n[0] == 127 && n[1] == 0 && n[2] == 0 && n[3] == 1)) {
        
        return 0;
    }
    return 1;
}

uint32_t IPToUInt(string ip) {
    int a, b, c, d;
    uint32_t addr = 0;
 
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;
 
    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

bool IsIPInRange(string ip, string network, string mask) {
    uint32_t ip_addr = IPToUInt(ip);
    uint32_t network_addr = IPToUInt(network);
    uint32_t mask_addr = IPToUInt(mask);
 
    uint32_t net_lower = (network_addr & mask_addr);
    uint32_t net_upper = (net_lower | (~mask_addr));
 
    if (ip_addr >= net_lower &&
        ip_addr <= net_upper)
        return true;
    return false;
}

unsigned int GetBufferSize(const char* source) {
    char c;
    unsigned int result = 0;
    while ((c = *source++) != '\0')
        result++;
    return result;
}

char* GetBody(char* source) {
    char c;
    unsigned int result = 0;
    int bsize = GetBufferSize(source);
    bool counter = 0;
    for (int i = 0; i < bsize; i++) {
        char ch = source[i];
        if (ch == '{') {
            return (source + i);
        }
    }
    return NULL;
}

std::chrono::system_clock::time_point stringToTimestamp(const std::string& dateString) {
    std::tm tm = {};
    std::istringstream ss(dateString);

    // Parse the date and time (up to seconds)
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) {
        throw std::runtime_error("Failed to parse date string");
    }

    // Convert tm to time_t (seconds since epoch)
    time_t time = std::mktime(&tm);

    // Handle fractional seconds
    char dot;
    long nanoseconds = 0;
    if (ss >> dot && dot == '.') {
        std::string fractional;
        ss >> fractional;
        // Convert fractional seconds to nanoseconds
        fractional.resize(9, '0'); // Ensure 9 digits for nanoseconds
        nanoseconds = std::stol(fractional);
    }

    // Combine seconds and nanoseconds into a time_point
    auto duration = std::chrono::seconds(time) + std::chrono::nanoseconds(nanoseconds);
    return std::chrono::system_clock::time_point(duration);
}

size_t findAlertflexSubstring(const string& str) {
    return str.find("alertflex");
}