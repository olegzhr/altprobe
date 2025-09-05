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

#ifndef FALCO_H
#define	FALCO_H

#include "hiredis.h"

#include "sinks.h"
#include "config.h"
#include "source.h"

using namespace std;
namespace bpt = boost::property_tree;

class OutputFields
{
public:
    
    string fd_cip;  // client IP address.
    string fd_sip;  // server IP address.
    unsigned int fd_cport; // for TCP/UDP FDs, the client port.
    unsigned int fd_sport; // for TCP/UDP FDs, server port.
    
    string fd_path; // file path
    string user_name;
        
    unsigned int proc_pid; 
    string proc_cmdline; 
    string proc_name;
    string proc_cwd; //process dir
    
    string container_id;
    string container_name;
    string container_image;
    
    string name_space;
    string pod_id;
    string pod_name;
    
    void Reset() {
        
        fd_cip.clear();
        fd_sip.clear();
        fd_cport = 0;
        fd_sport = 0;
                
        fd_path.clear();
        user_name.clear();
                
        proc_pid = 0;
        proc_cmdline.clear();
        proc_name.clear();
        proc_cwd.clear();
        
        container_id.clear();
        container_name.clear();
        container_image.clear();
        name_space.clear();
        pod_id.clear();
        pod_name.clear();
    }
};

//  Falcoo record                              
class FalcoRecord {
public:
    string record_type;
    bpt::ptree output_fields; 
    OutputFields fields;
    
    string output;
    string hostname;
    string source;
    string rule;
    string priority;
    int level;
    int severity;
    bpt::ptree tags;
    std::vector<string> list_cats;
    string timestamp; 
    
    void Reset() {
        record_type = "host";
        output_fields.clear(); 
        fields.Reset();
        output.clear();
        hostname.clear();
        source.clear();
        rule.clear();
        priority.clear();
        level = 0;
        severity = 0;
        tags.clear();
        list_cats.clear();
        timestamp.clear();
    }
};

class Falco : public Source {
public:
    
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    //Falco record
    FalcoRecord rec;
    
    bpt::ptree pt, pt1;
    stringstream ss, ss1;
    
    Falco (string skey, string ekey) : Source(skey, ekey) {
        json_report.reserve(100000);
        ClearRecords();
        ResetStreams();
        ferror_counter = 0;
    }
    
    void ResetStreams() {
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
    
    int ParsJson();
    void CreateLogRecord ();
    void SendAlert();
        
    void ClearRecords() {
	rec.Reset();
        json_report.clear();
        ResetJsontree();
    }
};

extern boost::lockfree::spsc_queue<string> q_logs_falco;

#endif	/* FALCO_H */