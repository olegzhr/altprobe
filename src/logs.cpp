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

#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <bits/stl_vector.h>

#include "logs.h"
#include "applog.h"
#include "suricata.h"
#include "falco.h"

int Logs::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    return 1;
}

int Logs::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void Logs::Close() {
    sk.Close();
}

int Logs::Go(void) {
    
    while (!q_logs_app.empty()) {
        q_logs_app.pop(rec);
        logs_list.push_back(rec);
        counter++;
    }   
    
    while (!q_logs_suricata.empty()) {
        q_logs_suricata.pop(rec);
        logs_list.push_back(rec);
        counter++;
    }   
    
    while (!q_logs_falco.empty()) {
        q_logs_falco.pop(rec);
        logs_list.push_back(rec);
        counter++;
    } 
        
    if (counter < 100 && timeout < 10) {
        usleep(GetGosleepInterval()*60);
        timeout++;
    } else {
        ProcessLogs();
        counter = 0;
        timeout = 0;
    }
    
    return 1;
}

void Logs::ProcessLogs() {
    
    if (!logs_list.empty()) {
        json_report.clear();
        json_report = "{ \"logs\" : [";
    
        bool first = true;
        for(const auto& log : logs_list) {
            if (!first) {
                json_report += " ,";
            }
            json_report += log;
            first = false;
        }
    
        json_report += " ] }";
        logs_list.clear();
            
        ss << json_report;
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(ss);
        boost::iostreams::copy(in, comp);
        boost::iostreams::close(in);

        int rep_size = comp.str().length();
                
        //string s = std::to_string(rep_size);
        //string output = "stat compressed = " + s;
        //SysLog((char*) output.c_str());
        bd.data = comp.str();
        bd.et = LOG;
        sk.SendMessage(&bd);
        
        ResetStreams();
    }
}
