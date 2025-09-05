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
 
#include <stdio.h>
#include <stdlib.h>
#include "supp.h"
#include "falco.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

boost::lockfree::spsc_queue<string> q_logs_falco{LOGS_QUEUE_SIZE};

int Falco::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (falco_log_status) {
        fp = fopen(falco_log.c_str(), "r");
        if(fp == NULL) {
            SysLog("failed open falco log file");
            return source_status = 0;
        }
        
        fseek(fp,0,SEEK_END);
        stat(falco_log.c_str(), &buf);    
        file_size = (unsigned long) buf.st_size;
    
    } else {
        if (redis_status == 1) {
            c = redisConnect(sk.redis_host.c_str(), sk.redis_port);
            if (c != NULL && c->err) {
                // handle error
                SysLog("failed open redis server");
                source_status = 0;
            }
        } else source_status = 0;
    }
    
    return source_status;
}

void Falco::Close() {
    
    sk.Close();
    
    if (source_status == 1) {
        
        if (falco_log_status) {
            if (fp != NULL) fclose(fp);
        } else {
            if (redis_status == 1) redisFree(c);
        }
        
        source_status = 0;
    }
}

void Falco::IsFileModified() {
    
    int ret = stat(falco_log.c_str(), &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            if (fp != NULL) fclose(fp);
            fp = fopen(falco_log.c_str(), "r");
                        
            if (fp == NULL) return;
            else {
                fseek(fp,0,SEEK_SET);
                int ret = stat(falco_log.c_str(), &buf);
                
                if (ret != 0) {
                    fp = NULL;
                    return;
                }
                
                file_size = (unsigned long) buf.st_size;
                return;
            }
        }
        
        file_size = current_size;
        return;
    } 
    
    fp = NULL;
}

int Falco::ReadFile() {
    
    if (fp == NULL) IsFileModified();
    else {
        if (fgets(file_payload, OS_PAYLOAD_SIZE, fp) != NULL) {
            ferror_counter = 0;
            return 1;
        } else {
            ferror_counter++;
            clearerr(fp);
        }
            
        if(ferror_counter > EOF_COUNTER) {
            IsFileModified();
            ferror_counter = 0;
        }
    } 
    
    return 0;
}

int Falco::Go(void) {
    int res = 0;
    
    ClearRecords();
        
    if (source_status) {
        
        if (falco_log_status) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading falco events from log");
                return 1;
            }
        
            if (res == 0) {
                usleep(GetGosleepInterval()*60);
                return 1;
            } else res = ParsJson();
        
        } else {
            // read data from redis
            reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
            if (!reply) {
                freeReplyObject(reply);
                return 1;
            }
        
            if (reply->type == REDIS_REPLY_STRING) {
                res = ParsJson();
            } else {
                freeReplyObject(reply);
                usleep(GetGosleepInterval()*60);
                return 1;
            }
        }
        
        if (res == 1) {
            if (enable_logs) CreateLogRecord ();
            if (enable_alerts) SendAlert();
            else if (pipeline_name.compare("") && pipeline_name.compare("indef")) SendAlert();
        }
        if (redis_status == 1) freeReplyObject(reply);
    } 
    else usleep(GetGosleepInterval()*60);
            
    return 1;
}

int Falco::ParsJson() {
    string message;
    
    try {
        if (falco_log_status) {
            json_report.assign(file_payload, GetBufferSize(file_payload));
            ss << json_report;
        }  else {
            json_report.assign(reply->str, GetBufferSize(reply->str));
            ss1 << json_report;
            bpt::read_json(ss1, pt1);
            
            message = pt1.get<string>("message","");
            
            if ((message.compare("") == 0)) {
                ResetStreams();
                return 0;
            }
            ss << message;
        }
        
        bpt::read_json(ss, pt);
    
        string output = pt.get<string>("output", "indef");
        ReplaceAll(output, "\"", "");
        rec.output = output;
    
        rec.hostname = pt.get<string>("hostname", "indef");
    
        rec.source = pt.get<string>("source", "indef");
    
        rec.rule = pt.get<string>("rule","");
    
        rec.priority = pt.get<string>("priority", "indef");
        rec.level = 0;
        if (rec.priority.compare("Emergency") == 0) rec.level = 7;
        if (rec.priority.compare("Alert") == 0) rec.level = 6;
        if (rec.priority.compare("Critical") == 0) rec.level = 5;
        if (rec.priority.compare("Error") == 0) rec.level = 4;
        if (rec.priority.compare("Warning") == 0) rec.level = 3;
        if (rec.priority.compare("Notice") == 0) rec.level = 2;
        if (rec.priority.compare("Info") == 0) rec.level = 1;
        if (rec.priority.compare("Debug") == 0) rec.level = 0;
    
        if (rec.level < 3) {
            rec.severity = 0;
        } else {
            if (rec.level == 3) {
                rec.severity = 1;
            } else {
                if (rec.level < 6) {
                    rec.severity = 2;
                } else {
                    rec.severity = 3;
                }
            }
        }  
    
        try {
            rec.tags = pt.get_child("tags");
        
            BOOST_FOREACH(bpt::ptree::value_type &v, rec.tags) {
                assert(v.first.empty()); 
                rec.list_cats.push_back(v.second.data());
            }
        } catch (bpt::ptree_bad_path& e) {}
    
        rec.timestamp = pt.get<string>("time","");
    
        boost::optional< bpt::ptree& > child = pt.get_child_optional( "output_fields" );
        if( child ) {
            rec.output_fields = pt.get_child("output_fields");
    
            rec.fields.fd_cip = rec.output_fields.get<string>(bpt::ptree::path_type("fd.cip", '/'),"indef");
            rec.fields.fd_sip = rec.output_fields.get<string>(bpt::ptree::path_type("fd.sip", '/'),"indef");
            rec.fields.fd_cport = rec.output_fields.get<int>(bpt::ptree::path_type("fd.cport", '/'),0);
            rec.fields.fd_sport = rec.output_fields.get<int>(bpt::ptree::path_type("fd.sport", '/'),0);
        
            rec.fields.fd_path = rec.output_fields.get<string>(bpt::ptree::path_type("fd.name", '/'),"indef");
            rec.fields.user_name = rec.output_fields.get<string>(bpt::ptree::path_type("user.name", '/'),"indef");
                
            rec.fields.proc_pid = rec.output_fields.get<int>(bpt::ptree::path_type("proc.pid", '/'),0);
            rec.fields.proc_cmdline = rec.output_fields.get<string>(bpt::ptree::path_type("proc.cmdline", '/'),"indef");
            rec.fields.proc_name = rec.output_fields.get<string>(bpt::ptree::path_type("proc.name", '/'),"indef");
            rec.fields.proc_cwd = rec.output_fields.get<string>(bpt::ptree::path_type("proc.cwd", '/'),"indef");  
    
            rec.fields.container_id = rec.output_fields.get<string>(bpt::ptree::path_type("container.id", '/'),"indef");
            if (!rec.fields.container_id.compare("indef")) 
                if (!rec.fields.container_id.compare("host")) 
                    rec.record_type = "container";
            rec.fields.container_name = rec.output_fields.get<string>(bpt::ptree::path_type("container.name", '/'),"indef");
            if (!rec.fields.container_name.compare("indef"))
                if (!rec.fields.container_id.compare("host")) 
                    rec.record_type = "container";
            rec.fields.container_image = rec.output_fields.get<string>(bpt::ptree::path_type("container.image", '/'),"indef");
            if (!rec.fields.container_image.compare("indef"))
                if (!rec.fields.container_id.compare("host")) 
                    rec.record_type = "container";
        
            rec.fields.pod_id = rec.output_fields.get<string>(bpt::ptree::path_type("k8s.pod.id", '/'),"indef");
            if (!rec.fields.pod_id.compare("indef"))
                if (!rec.fields.container_id.compare("host")) 
                    rec.record_type = "container";
            rec.fields.pod_name = rec.output_fields.get<string>(bpt::ptree::path_type("k8s.pod.name", '/'),"indef");
            if (!rec.fields.pod_name.compare("indef")) 
                if (!rec.fields.container_id.compare("host")) 
                    rec.record_type = "container";
            rec.fields.name_space = rec.output_fields.get<string>(bpt::ptree::path_type("k8s.ns.name", '/'),"indef");
            if (!rec.fields.name_space.compare("indef")) 
                if (!rec.fields.container_id.compare("host")) 
                    rec.record_type = "container";
        }
    } catch (const exception & ex) {
        ResetStreams();
        SysLog((char*) ex.what());
        return 0;
    } 
    ResetStreams();
    return 1;
}

void Falco::CreateLogRecord() {
    try {
        json_report.clear();
        json_report.append("{\"type_uid\": 200401 ,\"activity_id\": 1 ");
        json_report.append(",\"category_uid\": 2, \"category_name\": \"Findings\"");
        json_report.append(",\"class_uid\": 2004, \"class_name\": \"Detection Finding\"");
        json_report.append(", \"metadata\": { \"log_name\":\"alertflex\", \"log_provider\": \"");
        json_report.append(probe_name);
        json_report.append("\",\"logged_time\": ");
        
        auto now = std::chrono::system_clock::now();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        json_report.append(std::to_string(milliseconds));
        
        json_report.append(", \"version\":\"1.1.0\", \"product\": ");
        json_report.append("{ \"vendor_name\": \"Cloud Native Computing Foundation\", \"name\": \"Falco\" } }");
    
        json_report.append(", \"finding_info\": { \"title\": \"");
        json_report.append(rec.rule);
        json_report.append("\", \"uid\": \"");
        json_report.append(rec.source);
        json_report.append("\" }, \"message\": \"");     
        json_report.append(rec.output);
        json_report.append("\", \"device\": { \"hostname\": \"");
        json_report.append(rec.hostname);
        json_report.append("\", \"type_id\": 1, \"type\": \"server\" }");
    
        switch (rec.severity) {
            case 0: json_report.append(", \"severity_id\": 99, \"severity\": \"Informational\"");
                break;
            case 1: json_report.append(", \"severity_id\": 1, \"severity\": \"Informational\"");
                break;
            case 2: json_report.append(", \"severity_id\": 2, \"severity\": \"Low\"");
                break;
            case 3: json_report.append(", \"severity_id\": 3, \"severity\": \"Medium\"");
                break;
            case 4: json_report.append(", \"severity_id\": 4, \"severity\": \"Medium\"");
                break;
            case 5: json_report.append(", \"severity_id\": 5, \"severity\": \"High\"");
                break;
            case 6: json_report.append(", \"severity_id\": 6, \"severity\": \"High\"");
                break;
            case 7: json_report.append(", \"severity_id\": 6, \"severity\": \"High\"");
                break;
            default: json_report.append(", \"severity_id\": 0, \"severity\": \"Informational\"");
        }
    
        json_report.append(", \"time\": ");
        
        auto timestamp = stringToTimestamp(rec.timestamp);
        auto duration = timestamp.time_since_epoch();
        //auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        //json_report.append(std::to_string(seconds));
        json_report.append(std::to_string(milliseconds));
        
        json_report.append(", \"timezone_offset\": ");
        json_report.append(std::to_string(timezone_offset)); 
        json_report.append(" }");
    
        q_logs_falco.push(json_report);
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void Falco::SendAlert() { 
    try {
        switch (rec.severity) {
            case 0: sk.alert.alert_severity = "Info";
                break;
            case 1: sk.alert.alert_severity = "Info";
                break;
            case 2: sk.alert.alert_severity = "Low";
                break;
            case 3: sk.alert.alert_severity = "Medium";
                break;
            case 4: sk.alert.alert_severity = "Medium";
                break;
            case 5: sk.alert.alert_severity = "High";
                break;
            case 6: sk.alert.alert_severity = "Critical";
                break;
            case 7: sk.alert.alert_severity = "Critical";
                break;
            default: sk.alert.alert_severity = "Info";
        }
    
        sk.alert.alert_source = "Falco";
        sk.alert.alert_rule = rec.rule;
        sk.alert.alert_message = rec.output;
        sk.alert.src_ip = rec.fields.fd_cip;
        sk.alert.dst_ip = rec.fields.fd_sip;
        sk.alert.src_port = rec.fields.fd_cport;
        sk.alert.dst_port = rec.fields.fd_sport;
        sk.alert.user_name = rec.fields.user_name;
        sk.alert.file_name = rec.fields.fd_path;
        sk.alert.process_id = rec.fields.proc_pid;
        sk.alert.process_name = rec.fields.proc_name;
        sk.alert.container_id = rec.fields.container_id;
        sk.alert.container_name = rec.fields.container_name;
        sk.alert.name_space = rec.fields.name_space;
        sk.alert.pod_id = rec.fields.name_space;
        sk.alert.pod_name = rec.fields.name_space;
        sk.alert.http_hostname = "indef";
        sk.alert.http_port = 0;
        sk.alert.http_url = "indef";
        sk.alert.http_content_type = "indef";
        sk.alert.http_request_body = "indef";
        sk.alert.http_method = "indef";
        sk.alert.http_status = 0;
        sk.alert.original_time = rec.timestamp; 
    
        sk.SendAlert();
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    } 
}