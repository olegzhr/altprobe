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

#ifndef APPLOG_H
#define	APPLOG_H

#include "hiredis.h"

#include "sinks.h"
#include "config.h"
#include "source.h"

using namespace std;
namespace bpt = boost::property_tree;

struct LogRecord {
    string timestamp;
    string level;
    int severity_id;
    string logger_name;
    string file_info;
    string message;
    boost::optional<bpt::ptree> structured_data;
    string extra_data;
    
    void Reset() {
        timestamp.clear(); 
        level.clear();
        severity_id = 0;
        logger_name.clear();
        message.clear();
        extra_data.clear();
        structured_data.reset();
    }
};

class AppLog : public Source {
public:
    
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    LogRecord rec;
    
    bpt::ptree pt;
    stringstream ss, ss1;
    
    AppLog (string skey, string ekey) : Source(skey, ekey) {
        json_report.reserve(100000);
        ferror_counter = 0;
    }
    
    int Open();
    void Close();
    int ReadFile();
    void IsFileModified();
    int Go();
    
    int ParsLogLine();
    void CreateLogRecord ();
    void SendAlert();
    
    void ClearRecords() {
        rec.Reset();
        json_report.clear();
        ResetJsontree();
        ResetStreams();
    }
    
    void ResetStreams() {
        ss.str("");
        ss.clear();
        ss1.str("");
        ss1.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_app;

#endif	/* APPLOG_H */