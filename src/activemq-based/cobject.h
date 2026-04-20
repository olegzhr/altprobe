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

#ifndef COBJECT_H
#define	COBJECT_H

#include "main.h"
#include "config.h"

using namespace std;

class CObject {
public:
    static bool cobject_config_flag;
    
    // collector
    static string project_id;
    static string probe_name;
    static string sensors_group;
    
    static bool is_docker;
    
    static int timezone_offset;
    static int report_interval;
    
    // controller
    static string url;
    static string user;
    static string pwd;
    static bool user_pwd;
    
    static bool enable_alerts;
    static bool enable_logs;
    
    // scanners
    static string path_workspace;
    static string path_output;
    
    // sensors
    static string app_log; 
    static bool app_log_status;
    static bool app_redis_status;
    static string falco_log; 
    static bool falco_log_status;
    static bool falco_redis_status;
    static string suricata_log; 
    static bool suricata_log_status;
    static bool suricata_redis_status;
    
    static string redis_host;
    static int redis_port;
        
    // extra non config parameters
    static int gosleep_interval;
    char collector_time[OS_DATETIME_SIZE]; 
    static char sys_log_info[OS_LONG_HEADER_SIZE];
    
    // scan pipeline info
    static string pipeline_name;
    static string pipeline_task;
    static string last_test_time;
    
    CObject () {
        project_id.clear();
        probe_name.clear();
        sensors_group.clear();
        
        url.clear();
        user.clear();
        pwd.clear();
        //cert.clear();
        //cert_verify.clear();
        //key.clear();
        //key_pwd.clear();
        
        path_workspace.clear();
        path_output.clear();
                
        app_log.clear();
        falco_log.clear(); 
        suricata_log.clear();
        redis_host.clear();
    }
    
    virtual int GetConfig();
    
    string GetSensorsGroup()  { return sensors_group; }
    int GetGosleepInterval() { return gosleep_interval; }
    int GetReportInterval() { return report_interval; }
    
    bool IsRunningInDockerContainer();
    string GetProbeTime();
    void ReplaceAll(string& input, const string& from, const string& to);
    void SysLog(char* info);
};

enum event_types { ALERT = 1, LOG = 2, TEST = 3, STATUS = 4 };

class Event {
public:
    event_types et;
};

class ByteData : public Event {
public:   
    string data;
            
    void Reset() {
        data.clear();
    }
    
    ByteData () {
        data.clear();
    }
};

class Test : public ByteData {
public:
    string pipeline_name;
    string pipeline_task;
    string test_type;
    string test_corr;
    string job_name;
    string asset_name;
    string asset_target;
    string output_format;
        
    void Reset() {
        ByteData::Reset();
        pipeline_name.clear();
        pipeline_task.clear();
        test_type.clear();
        test_corr.clear();
        job_name.clear();
        asset_name.clear();
        asset_target.clear();
        output_format.clear();
    }
    
    Test () {
        et = TEST;
        pipeline_name.clear();
        pipeline_task.clear();
        test_type.clear();
        test_corr.clear();
        job_name.clear();
        asset_name.clear();
        asset_target.clear();
        output_format.clear();
    }
};

class Alert : public Event {
public:   
    // Record
    string alert_uuid;
    string alert_severity;
    string alert_source;
    string alert_rule;
    string alert_message;
    string src_ip;
    unsigned int src_port;
    string dst_ip;
    unsigned int dst_port;
    string file_name;
    string user_name;
    unsigned int process_id;
    string process_name;
    string container_id;
    string container_name;
    string name_space;
    string pod_id;
    string pod_name;
    unsigned long http_flowid;
    string http_hostname;
    unsigned int http_port;
    string http_url;
    string http_method;
    string http_content_type;
    string http_request_body;
    unsigned int http_status;
    string original_time;
    
    Alert () {
        et = ALERT;
        Reset();
    }
        
    void Reset() {
        alert_uuid.clear();
        alert_severity.clear();
        alert_source.clear();
        alert_rule.clear();
        alert_message.clear();
        src_ip.clear();
        src_port = 0;
        dst_ip.clear();
        dst_port = 0;
        file_name.clear();
        user_name.clear();
        process_id = 0;
        process_name.clear();
        container_id.clear();
        container_name.clear();
        name_space.clear();
        pod_id.clear();
        pod_name.clear();
        http_hostname.clear();
        http_port = 0;
        http_url.clear();
        http_method.clear();
        http_content_type.clear();
        http_request_body.clear();
        http_status = 0;
        original_time.clear();
    }
    
    void CreateAlertUUID(void);
};

#endif	/* COBJECT_H */
