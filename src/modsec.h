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

#ifndef MODSEC_H
#define MODSEC_H

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include "modsecurity/rule_message.h"

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <chrono>
#include <exception>
#include <list>
#include <memory>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include "sinks.h"
#include "config.h"
#include "source.h"
#include "http.h"
#include "detection.h"
#include "correlator.h"

using namespace std;

class Modsec : public Source {
public:
    
    int counter;
    int timeout;
    
    unique_ptr<modsecurity::ModSecurity> modsec;
    unique_ptr<modsecurity::RulesSet> rules;
    
    Http http;

    // ModSecurity calls logCb during request and response inspection. Exclude
    // response content from request-phase API Guard classification.
    bool current_request_inspection_ = false;

    static Modsec* currentInstance;
    
    Modsec();
    
    static void logCb(void *data, const void *ruleMessagev);
        
    void createLogRecord(const void *ruleMessagev);
    
    virtual bool Open();
    virtual void Close();
    virtual bool Go();
    
    bool loadCRSRules();
    
    bool processHttpRequest(const string& clientIP,
        const string& serverIP,
        int serverPort,
        const string& uri,
        const string& method,
        const string& httpVersion,
        const vector<pair<string, string>>& headers,
        const string& body = "");
    
    // Check if transaction has intervention (blocking action)
    bool hasIntervention(modsecurity::Transaction& transaction);
    
    SignalType mapRuleId(int id);
    
};

vector<pair<string, string>> convertHeaders(const string& jsonString);

#endif /* MODSEC_H */


