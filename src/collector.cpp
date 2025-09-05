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

#include "collector.h"

int Collector::GetConfig() {
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    return 1;
}

int  Collector::Open() {
    if (!sk.Open()) return 0;
    
    return 1;
}

void  Collector::Close() {
    sk.Close();
}

int Collector::Go(void) {
    
    long counter_seconds = 0;
                
    while (sk.GetReportInterval() > counter_seconds) {
        counter_seconds++;
        sleep(1);
    }
        
    UpdateProbeStatus();
    SysLog("update probe status has been done");
    
    return 1;
}

void Collector::UpdateProbeStatus() {
    
    stringstream ss;
    
    int local_enable_alerts = 0;
    if (enable_alerts) local_enable_alerts = 1;
    else if (pipeline_name.compare("") && pipeline_name.compare("indef")) local_enable_alerts = 1;
    
    ss << "{ \"report_interval\": ";
    ss << report_interval;
    ss << ", \"enable_alerts\": ";
    ss << local_enable_alerts;
    ss << ", \"enable_logs\": ";
    ss << enable_logs;
    ss << ", \"run_mode\": \"";
    string run_mode;
    if (is_docker) run_mode = "docker";
    else run_mode = "host";
    ss << run_mode;
    ss << "\", \"path_workspace\": \"";
    ss << path_workspace;
    ss << "\", \"path_output\": \"";
    ss << path_output;
    ss << "\", \"app_log_status\": ";
    ss << app_log_status;
    ss << ", \"app_redis_status\": ";
    ss << app_redis_status;
    ss << ", \"falco_log_status\": ";
    ss << falco_log_status;
    ss << ", \"falco_redis_status\": ";
    ss << falco_redis_status;
    ss << ", \"suricata_log_status\": ";
    ss << suricata_log_status;
    ss << ", \"suricata_redis_status\": ";
    ss << suricata_redis_status;
    ss << ", \"last_test_time\": \"";
    ss << last_test_time;
    ss << "\" }";
        
    boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
    in.push(boost::iostreams::gzip_compressor());
    in.push(ss);
    boost::iostreams::copy(in, comp);
    boost::iostreams::close(in);

    bd.data = comp.str();
    bd.et = STATUS;
    sk.SendMessage(&bd);
    
    boost::iostreams::close(in);
    ss.clear();
    comp.str("");
    comp.clear();
}