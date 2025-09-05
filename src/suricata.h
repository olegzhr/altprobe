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

#ifndef SURICATA_H
#define	SURICATA_H

#include "sinks.h"
#include "config.h"
#include "source.h"

using namespace std;

class SuricataAlert {
public:
    string action;
    unsigned int gid;
    long signature_id;
    string signature;
    string category;
    unsigned int severity;
    
    void Reset() {
        action.clear();
        gid = 0;
        signature_id = 0;
        signature.clear();
        category.clear();
        severity = 0;
    }
};

class SuricataHttp {
public:
    string hostname;
    unsigned int  port;
    string url;
    string user_agent;
    string request_headers;
    string request_body;
    string content_type;
    string method;
    string protocol;
    unsigned int status;
    
    
    void Reset() {
        hostname.clear();
        port = 0;
        url.clear();
        user_agent.clear();
        request_headers.clear();
        request_body.clear();
        content_type.clear();
        method.clear();
        protocol.clear();
        status = 0;
    }
};

//  Suricata record                              
class SuricataRecord {
public:
    
    // *** Common fields
    string ref_id;
    int event_type;
    string time_stamp;
    string iface;
    unsigned long flow_id;
            
    string src_ip;
    unsigned int src_port;
    
    string dst_ip;
    unsigned int dst_port;
    
    string sensor;
    string protocol;
            
    //  Record  Alert 
    SuricataAlert alert;
    //  Record  HTTP
    SuricataHttp http;
    
    
    void Reset() {
        //reset rule class object
        ref_id.clear();
        event_type = 0;
        time_stamp.clear();
        iface.clear();
        flow_id = 0;
        src_ip.clear();
        src_port = 0;
        dst_ip.clear();
        dst_port = 0;
        protocol.clear();
        sensor.clear();    
        
        alert.Reset();
        http.Reset();
    }
};

namespace bpt = boost::property_tree;

class Suricata : public Source {
public: 
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    //Suricata record
    SuricataRecord rec;
    unsigned long alert_flowid;
    
    bpt::ptree pt, pt1;
    stringstream ss, ss1;
    
    Suricata (string skey, string ekey) : Source(skey, ekey) {
        json_report.reserve(100000);
        ClearRecords();
        ResetStream();
        ferror_counter = 0;
    }
    
    void ResetStream() {
        ss.str("");
        ss.clear();
        ss1.str("");
        ss1.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
        pt1.clear();
    }
    
    int Open();
    void Close();
    int ReadFile();
    void IsFileModified();
    int Go();
        
    int ParsJson (int output_type);
    void CleanJsonArrayToString(const bpt::ptree& array);
    void CreateLogRecord ();
    void SendAlert ();
                                    
    void ClearRecords() {
        rec.Reset();
        ResetJsontree();
        json_report.clear();
    }
};

extern boost::lockfree::spsc_queue<string> q_logs_suricata;

#endif	/* SURICATA_H */