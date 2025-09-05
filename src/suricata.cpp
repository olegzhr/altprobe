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
#include "suricata.h"
#include <boost/algorithm/string/replace.hpp>

boost::lockfree::spsc_queue<string> q_logs_suricata{LOGS_QUEUE_SIZE};

int Suricata::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (suricata_log_status) {
        
        fp = fopen(suricata_log.c_str(), "r");
        if(fp == NULL) {
            SysLog("failed open suricata log file");
            return source_status = 0;
        }
        
        fseek(fp,0,SEEK_END);
        stat(suricata_log.c_str(), &buf);    
        file_size = (unsigned long) buf.st_size;
    
    } else {
        
        if (redis_status == 1) {
            
            c = redisConnect(sk.redis_host.c_str(), sk.redis_port);
    
            if (c != NULL && c->err) {
                // handle error
                SysLog("failed open redis server interface");
                source_status = 0;
            }
        
        } else source_status = 0;
    }
    
    return source_status;
}

void Suricata::Close() {
    
    sk.Close();
    
    if (source_status > 0) {
        
        if (suricata_log_status) {
            if (fp != NULL) fclose(fp);
        } 
        
        if (redis_status == 1) redisFree(c);
        
        source_status = 0;
    }
    
}

void Suricata::IsFileModified() {
    
    int ret = stat(suricata_log.c_str(), &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            
            if (fp != NULL) fclose(fp);
            fp = fopen(suricata_log.c_str(), "r");
                        
            if (fp == NULL) return;
            else {
                
                fseek(fp,0,SEEK_SET);
                int ret = stat(suricata_log.c_str(), &buf);
                
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

int Suricata::ReadFile() {
    
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

int Suricata::Go(void) {
    
    int res = 0;
        
    ClearRecords();
    
    if (source_status) {
        
        if (suricata_log_status == 1) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading suricata events from log");
                return 1;
            }
            
            if (res == 0) {
                usleep(GetGosleepInterval()*60);
                return 1;
            } else res = ParsJson(1);
        
        } else {
        
            reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
            
            if (!reply) {
                freeReplyObject(reply);
                return 1;
            }
        
            if (reply->type == REDIS_REPLY_STRING) {
                res = ParsJson(2);
            } else {
                freeReplyObject(reply);
                usleep(GetGosleepInterval()*60);
                return 1;
            }
        }
        
        if (res > 0) {
            if (enable_logs) CreateLogRecord();
            if (res == 1) {
                if (enable_alerts) SendAlert();
                else if (pipeline_name.compare("") && pipeline_name.compare("indef")) SendAlert();
            }
        }
        
        if (redis_status == 1) freeReplyObject(reply);
    } 
    else usleep(GetGosleepInterval()*60);
            
    return 1;
}

int Suricata::ParsJson (int output_type) {
    
    try {
    
        if (output_type == 1) {
            json_report.assign(file_payload, GetBufferSize(file_payload));
        } else {
            json_report.assign(reply->str, GetBufferSize(reply->str));
        }
    
        ss << json_report;
        bpt::read_json(ss, pt);
    
        if (output_type == 2) {
            string sensor_name = pt.get<string>("firewall_name", "indef");
        
            if (sensor_name.compare("indef") != 0) {
            
                rec.sensor = sensor_name;
            
                ss1 << json_report;
                bpt::read_json(ss1, pt1);
                pt = pt1.get_child("event");
        
            } else {
                rec.sensor = probe_name;
            }
        } else {
            rec.sensor = probe_name;
        }
    
        string event_type = pt.get<string>("event_type","");
    
        if (event_type.compare("alert") == 0) {
        
            rec.event_type = 1;
        
            rec.time_stamp = pt.get<string>("timestamp","");
        
            rec.iface = pt.get<string>("in_iface","");
        
            alert_flowid = pt.get<long>("flow_id",0);
        
            rec.src_ip = pt.get<string>("src_ip","");
            rec.src_port = pt.get<int>("src_port",0);
        
            rec.dst_ip = pt.get<string>("dest_ip","");
            rec.dst_port = pt.get<int>("dest_port",0);
        
            rec.protocol = pt.get<string>("proto","");
                
            // alert record
            rec.alert.action = pt.get<string>("alert.action","");
                
            rec.alert.gid = pt.get<int>("alert.gid",0); 
        
            rec.alert.signature_id = pt.get<long>("alert.signature_id",0); 
                
            rec.alert.signature = pt.get<string>("alert.signature","");
        
            rec.alert.category = pt.get<string>("alert.category","");
        
            rec.alert.severity = pt.get<int>("alert.severity",0);
        
            // http record
            rec.http.hostname = pt.get<string>("http.hostname","indef");
            rec.http.port = pt.get<int>("http.http_port",0);
            rec.http.url = pt.get<string>("http.url","indef");
            rec.http.user_agent = pt.get<string>("http.http_user_agent","indef");
            rec.http.content_type = pt.get<string>("http.http_content_type","indef");
            rec.http.request_body = pt.get<string>("http.http_request_body_printable","indef");
            rec.http.method = pt.get<string>("http.http_method","indef");
            rec.http.protocol = pt.get<string>("http.protocol","indef");
            rec.http.status = pt.get<int>("http.status",0);
                        
            ResetStream();
            return rec.event_type;
        }
    
        if (event_type.compare("http") == 0) {
        
            rec.event_type = 2;
        
            rec.time_stamp = pt.get<string>("timestamp","");
        
            rec.iface = pt.get<string>("in_iface","");
        
            rec.flow_id = pt.get<long>("flow_id",0);
        
            rec.src_ip = pt.get<string>("src_ip","");
            rec.src_port = pt.get<int>("src_port",0);
        
            rec.dst_ip = pt.get<string>("dest_ip","");
            rec.dst_port = pt.get<int>("dest_port",0);
        
            rec.protocol = pt.get<string>("proto","");
        
            rec.http.hostname = pt.get<string>("http.hostname","indef");
            rec.http.url = pt.get<string>("http.url","indef");
            rec.http.user_agent = pt.get<string>("http.http_user_agent","indef");
            rec.http.content_type = pt.get<string>("http.http_content_type","indef");
            rec.http.method = pt.get<string>("http.http_method","indef");
            rec.http.protocol = pt.get<string>("http.protocol","indef");
            rec.http.status = pt.get<int>("http.status",0);
        
            pt1.clear();
            pt1 = pt.get_child("http.request_headers");
            CleanJsonArrayToString(pt1);
            rec.http.request_headers = ss.str();  
            boost::replace_all(rec.http.request_headers, "\n]", "]");
            ResetStream();
            return rec.event_type;
        } 
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    }
    
    ResetStream();
    return 0;
}

void Suricata::CleanJsonArrayToString(const bpt::ptree& array) {
    try {
        ss.str("");
        ss.clear();
        ss1.str("");
        ss1.clear();
        ss << "[";  // Manually start array

        bool first = true;
        for (const auto& item : array) {
            if (!first) ss1 << ",";
            first = false;

            boost::property_tree::write_json(ss1, item.second, false);
            ss << ss1.str();
        }

        ss << "]";  // Close array
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void Suricata::CreateLogRecord() {
    try {
        json_report.clear();
    
        switch (rec.event_type) {
            case 1:  {
                json_report.append("{\"type_uid\": 200401 ,\"activity_id\": 1 ");
                json_report.append(",\"category_uid\": 2, \"category_name\": \"Findings\"");
                json_report.append(",\"class_uid\": 2004, \"class_name\": \"Detection Finding\"");
                json_report.append(", \"metadata\": { \"uid\": \"");
                json_report.append(std::to_string(alert_flowid));
                json_report.append("\",\"log_name\":\"alertflex\", \"log_provider\": \"");
                json_report.append(probe_name);
                json_report.append("\",\"logged_time\": ");
                
                auto now = std::chrono::system_clock::now();
                auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                json_report.append(std::to_string(milliseconds));
                
                json_report.append(", \"version\":\"1.1.0\", \"product\": ");
                json_report.append("{ \"vendor_name\": \"The Open Information Security Foundation\", \"name\": \"Suricata\" } }");
            
                json_report.append(", \"finding_info\": { \"title\": \"");
                json_report.append(rec.alert.category);       
                json_report.append("\", \"uid\": \"");
                json_report.append(std::to_string(rec.alert.signature_id)); 
                json_report.append("\" }, \"message\": \"");     
                json_report.append(rec.alert.signature);
            
                json_report.append("\", \"device\": { \"hostname\": \"");
                json_report.append(rec.sensor);
                json_report.append("\", \"type_id\": 14, \"type\": \"other\" }");
            
                switch (rec.alert.severity) {
                    case 1: json_report.append(", \"severity_id\": 4, \"severity\": \"Critical\"");
                        break;
                    case 2: json_report.append(", \"severity_id\": 3, \"severity\": \"High\"");
                        break;
                    case 3: json_report.append(", \"severity_id\": 2, \"severity\": \"Medium\"");
                        break;
                    default: json_report.append(", \"severity_id\": 0, \"severity\": \"Low\"");
                }
            
                json_report.append(", \"time\": ");
                
                auto timestamp = stringToTimestamp(rec.time_stamp);
                auto duration = timestamp.time_since_epoch();
                milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
                json_report.append(std::to_string(milliseconds));
                
                json_report.append(", \"timezone_offset\": ");
                json_report.append(std::to_string(timezone_offset)); 
                json_report.append(" }");
                q_logs_suricata.push(json_report); }
            
                break;
                   
            case 2: // http record
            
                long type_uid = 400200;
                int activity_id = 0;
                string activity_name = "Unknown";
        
                if (rec.http.method.compare("") != 0) {
                    if (rec.http.method.compare("CONNECT") == 0) {
                        type_uid = 400201;
                        activity_id = 1;
                        activity_name = "Connect";
                    } else if (rec.http.method.compare("DELETE") == 0) {
                        type_uid = 400202;
                        activity_id = 2;
                        activity_name = "Delete";
                    } else if (rec.http.method.compare("GET") == 0) {
                        type_uid = 400203;
                        activity_id = 3;
                        activity_name = "Get";
                    } else if (rec.http.method.compare("HEAD") == 0) {
                        type_uid = 400204;
                        activity_id = 4;
                        activity_name = "Head";
                    } else if (rec.http.method.compare("OPTIONS") == 0) {
                        type_uid = 400205;
                        activity_id = 5;
                        activity_name = "Options";
                    } else if (rec.http.method.compare("POST") == 0) {
                        type_uid = 400206;
                        activity_id = 6;
                        activity_name = "Post";
                    } else if (rec.http.method.compare("PUT") == 0) {
                        type_uid = 400207;
                        activity_id = 7;
                        activity_name = "Put";
                    } else if (rec.http.method.compare("TRACE") == 0) {
                        type_uid = 400208;
                        activity_id = 8;
                        activity_name = "Trace";
                    } else {
                        type_uid = 400299;
                        activity_id = 99;
                        activity_name = rec.http.method;
                    }
                }
        
                json_report.append("{\"type_uid\": ");
                json_report.append(std::to_string(type_uid));
        
                json_report.append(",\"activity_id\":");
                json_report.append(std::to_string(activity_id));
        
                json_report.append(",\"activity_name\":\"");
                json_report.append(activity_name);
        
                json_report.append("\",\"category_uid\": 4, \"category_name\": \"Network Activity\"");
                json_report.append(",\"class_uid\": 4002, \"class_name\": \"HTTP Activity\"");
            
                json_report.append(",\"metadata\": { \"uid\": \"");
                json_report.append(std::to_string(rec.flow_id));
                json_report.append("\",\"log_name\":\"alertflex\", \"log_provider\": \"");
                json_report.append(probe_name);
                json_report.append("\",\"logged_time\": ");
        
                auto now = std::chrono::system_clock::now();
                auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                json_report.append(std::to_string(milliseconds));
                
                json_report.append(", \"version\":\"1.1.0\", \"product\": ");
                json_report.append("{ \"vendor_name\": \"The Open Information Security Foundation\", \"name\": \"Suricata\" } }");
                json_report.append(", \"src_endpoint\": { \"ip\": \"");
                json_report.append(rec.src_ip);
                json_report.append("\", \"port\": ");
                json_report.append(std::to_string(rec.src_port));
                json_report.append("}, \"dst_endpoint\": { \"ip\": \"");
                json_report.append(rec.dst_ip);
                json_report.append("\", \"port\": ");
                json_report.append(std::to_string(rec.dst_port));
                json_report.append("}, \"connection_info\": { \"protocol_name\": \"");
                json_report.append(rec.http.protocol);
                json_report.append("\", \"direction_id\": 0 }, ");
            
                json_report.append("\"http_request\": { \"user_agent\": \"");
                json_report.append(rec.http.user_agent);
                json_report.append("\", \"url\": { \"hostname\": \"");
                json_report.append(rec.http.hostname);
                json_report.append("\", \"path\": \"");
                json_report.append(rec.http.url);
                json_report.append("\" }, \"http_method\": \"");
                json_report.append(rec.http.method);
                json_report.append("\", \"version\": \"");
                json_report.append(rec.http.protocol);
                json_report.append("\" }, \"http_response\": { \"code\": ");
                json_report.append(std::to_string(rec.http.status));
                json_report.append(" }, \"severity_id\": 1, \"severity\": \"Informational\", \"time\": ");
                
                auto timestamp = stringToTimestamp(rec.time_stamp);
                auto duration = timestamp.time_since_epoch();
                milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
                
                json_report.append(std::to_string(milliseconds));
                json_report.append(", \"timezone_offset\": ");
                json_report.append(std::to_string(timezone_offset)); 
                json_report.append(" }");
                q_logs_suricata.push(json_report);
            
                if (alert_flowid == rec.flow_id > 0) {
                    json_report.clear();
                    json_report.append("{ \"category_name\": \"request_headers\", \"flow_id\": ");
                    json_report.append(std::to_string(alert_flowid));
                    json_report.append(", \"headers\": ");
                    json_report.append(rec.http.request_headers);
                    json_report.append(" }");
                    alert_flowid = 0;
                    q_logs_suricata.push(json_report);
                } 
            
                break;
        }
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void Suricata::SendAlert() {
    try {
        switch (rec.alert.severity) {
            case 1: sk.alert.alert_severity = "Critical";
                break;
            case 2: sk.alert.alert_severity = "High";
                break;
            case 3: sk.alert.alert_severity = "Medium";
                break;
            default: sk.alert.alert_severity = "Low";
        }
    
        sk.alert.alert_source = "Suricata";
        ss << rec.alert.signature_id;
        sk.alert.alert_rule = ss.str();
        ss.str("");
        ss.clear();
        sk.alert.alert_message = rec.alert.signature;
        sk.alert.src_ip = rec.src_ip;
        sk.alert.dst_ip = rec.dst_ip;
        sk.alert.src_port = rec.src_port;
        sk.alert.dst_port = rec.dst_port;
        sk.alert.user_name = "indef";
        sk.alert.file_name = "indef";
        sk.alert.process_id = 0;
        sk.alert.process_name = "indef";
        sk.alert.container_id = "indef";
        sk.alert.container_name = "indef";
        sk.alert.name_space = "indef";
        sk.alert.pod_id = "indef";
        sk.alert.pod_name = "indef";
        sk.alert.http_flowid = alert_flowid;
        sk.alert.http_hostname = rec.http.hostname;
        sk.alert.http_port = rec.http.port;
        sk.alert.http_url = rec.http.url;
        sk.alert.http_content_type = rec.http.content_type;
        sk.alert.http_request_body = rec.http.request_body;
        sk.alert.http_method = rec.http.method;
        sk.alert.http_status = rec.http.status;
        sk.alert.original_time = rec.time_stamp;  
    
        sk.SendAlert();
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    }
}