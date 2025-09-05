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
#include "applog.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

boost::lockfree::spsc_queue<string> q_logs_app{LOGS_QUEUE_SIZE};

int AppLog::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (app_log_status) {
        fp = fopen(app_log.c_str(), "r");
        if(fp == NULL) {
            SysLog("failed open app log file");
            return source_status = 0;
        }
        
        fseek(fp,0,SEEK_END);
        stat(app_log.c_str(), &buf);    
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

void AppLog::Close() {
    
    sk.Close();
    
    if (source_status == 1) {
        
        if (app_log_status) {
            if (fp != NULL) fclose(fp);
        } else {
            if (redis_status == 1) redisFree(c);
        }
        
        source_status = 0;
    }
}

void AppLog::IsFileModified() {
    
    int ret = stat(app_log.c_str(), &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            if (fp != NULL) fclose(fp);
            fp = fopen(app_log.c_str(), "r");
                        
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

int AppLog::ReadFile() {
    
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

int AppLog::Go(void) {
    int res = 0;
    
    ClearRecords();
        
    if (source_status) {
        
        if (app_log_status) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading app events from log");
                return 1;
            }
        
            if (res == 0) {
                usleep(GetGosleepInterval()*60);
                return 1;
            } else res = ParsLogLine();
        
        } else {
            // read data from redis
            reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
            if (!reply) {
                freeReplyObject(reply);
                return 1;
            }
        
            if (reply->type == REDIS_REPLY_STRING) {
                res = ParsLogLine();
            } else {
                freeReplyObject(reply);
                usleep(GetGosleepInterval()*60);
                return 1;
            }
        }
        
        if (res == 1) {
            if (enable_logs) CreateLogRecord();
            if (enable_alerts) SendAlert();
            else if (pipeline_name.compare("") && pipeline_name.compare("indef")) SendAlert();
        }
        if (redis_status == 1) freeReplyObject(reply);
    } 
    else usleep(GetGosleepInterval()*60);
            
    return 1;
}

int AppLog::ParsLogLine(void) {
        
    try {
        if (app_log_status) {
            json_report.assign(file_payload, GetBufferSize(file_payload));
        }  else {
            json_report.assign(reply->str, GetBufferSize(reply->str));
        }
        
        if (json_report.empty()) {
            return 0;
        }
        
        string single_line = json_report.substr(0, json_report.find('\n'));
        
        std::regex log_regex(
            R"((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4})\s+)"  // timestamp
            R"((\w+)\s+)"                                                  // level
            R"((?:\[([^\]]+)\]\s+)?)"                                      // optional logger name
            R"((\S+:\d+)\s+)"                                              // file info
            R"((.*?)\s*)"                                                  // message
            R"((\{.*\})?\s*$)"                                             // optional json
        );
        
        std::smatch matches;
        if (!std::regex_match(single_line, matches, log_regex)) {
            std::regex alt_regex(
                R"(\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4})\].*?\[(\w+)\].*?\[([^\]]*)\]\s*(.*))"
            );
        
            if (std::regex_match(single_line, matches, alt_regex)) {
                rec.timestamp = matches[1].str();
                string level = matches[2].str();
                
                if (level.compare("TRACE") == 0) {
                    rec.level = "Informational";
                    rec.severity_id = 1;
                }
                if (level.compare("VERBOSE") == 0) {
                    rec.level = "Informational";
                    rec.severity_id = 1;
                }
                if (level.compare("DEBUG") == 0) {
                    rec.level = "Informational";
                    rec.severity_id = 1;
                }
                if (level.compare("INFO") == 0) {
                    rec.level = "Informational";
                    rec.severity_id = 1;
                }
                if (level.compare("NOTICE") == 0) {
                    rec.level = "Low";
                    rec.severity_id = 2;
                }
                if (level.compare("WARN") == 0) {
                    rec.level = "Medium";
                    rec.severity_id = 3;
                }
                if (level.compare("WARNING") == 0) {
                    rec.level = "Medium";
                    rec.severity_id = 3;
                }
                if (level.compare("ERROR") == 0) {
                    rec.level = "High";
                    rec.severity_id = 4;
                }
                if (level.compare("CRITICAL") == 0) {
                    rec.level = "Critical";
                    rec.severity_id = 5;
                }
                if (level.compare("FATAL") == 0) {
                    rec.level = "Critical";
                    rec.severity_id = 5;
                }
                if (level.compare("ALERT") == 0) {
                    rec.level = "Critical";
                    rec.severity_id = 5;
                }
                if (level.compare("EMERGENCY") == 0) {
                    rec.level = "Critical";
                    rec.severity_id = 5;
                }
                
                rec.message = matches[4].str();
                rec.logger_name = "indef";
                rec.file_info = "indef";
                rec.extra_data = "indef";
                return 1;
            }
            return 0;
        }
        
        rec.timestamp = matches[1].str();
        rec.level = matches[2].str();
    
        if (matches[3].matched) {
            rec.logger_name = matches[3].str();
        }
    
        rec.file_info = matches[4].str();
        rec.message = matches[5].str();
        
        if (matches[6].matched) {
            try {
                ss << matches[6].str();
                bpt::read_json(ss, pt);
                rec.structured_data = pt;
                if (rec.structured_data) {
                    bpt::write_json(ss1, *rec.structured_data, false);
                    rec.extra_data = ss1.str();
                }
            } catch (const bpt::json_parser_error&) {
                // Ignore invalid JSON
                rec.extra_data = "indef";
            }
        }
    } catch (const exception & ex) {
        
        SysLog((char*) ex.what());
        return 0;
    } 
    return 1;
}

void AppLog::CreateLogRecord() {
    try {
        json_report.clear();
        json_report.append("{\"type_uid\": 600800 ,\"activity_id\": 0 ");
        json_report.append(",\"category_uid\": 6, \"category_name\": \"Application Activity\"");
        json_report.append(",\"class_uid\": 6008, \"class_name\": \"Application Error\"");
        json_report.append(", \"metadata\": { \"log_name\":\"alertflex\", \"log_provider\": \"");
        json_report.append(probe_name);
        json_report.append("\",\"logged_time\": ");
        
        auto now = std::chrono::system_clock::now();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        json_report.append(std::to_string(milliseconds));
        
        json_report.append(", \"version\":\"1.1.0\", \"product\": ");
        json_report.append("{ \"vendor_name\": \"indef\", \"name\": \"indef\" } }");
        json_report.append(",  \"message\": \"");     
        json_report.append(rec.message);
        json_report.append("\", ");
        json_report.append("\"severity_id\":");
        json_report.append(std::to_string(rec.severity_id));
        json_report.append(", \"severity\": \"");
        json_report.append(rec.level);
        json_report.append("\", \"time\": ");
        
        auto timestamp = stringToTimestamp(rec.timestamp);
        auto duration = timestamp.time_since_epoch();
        milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        json_report.append(std::to_string(milliseconds));
        
        
        json_report.append(", \"timezone_offset\": ");
        json_report.append(std::to_string(timezone_offset)); 
        json_report.append(" }");
    
        q_logs_app.push(json_report);
    } catch (const exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void AppLog::SendAlert() { 
    try {
        switch (rec.severity_id) {
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
    
        sk.alert.alert_source = "AppLog";
        sk.alert.alert_rule = rec.logger_name;
        sk.alert.alert_message = rec.message;
        sk.alert.src_ip = "indef";
        sk.alert.dst_ip = "indef";
        sk.alert.src_port = 0;
        sk.alert.dst_port = 0;
        sk.alert.user_name = "indef";
        sk.alert.file_name = rec.file_info;
        sk.alert.process_id = 0;
        sk.alert.process_name = "indef";
        sk.alert.container_id = "indef";
        sk.alert.container_name = "indef";
        sk.alert.name_space = "indef";
        sk.alert.pod_id = "indef";
        sk.alert.pod_name = "indef";
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

