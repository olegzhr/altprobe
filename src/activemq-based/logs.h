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

#ifndef LOGS_H
#define	LOGS_H

#include "source.h"

using namespace std;

class Logs : public Source {
public:  
    
    int counter;
    int timeout;
    
    std::stringstream ss, comp;
    
    string rec;
    ByteData bd;
    
    //logs 
    std::vector<string> logs_list;
    
    Logs () {
        counter = 0;
        timeout = 0;
        json_report.reserve(100000);
        ResetStreams();
    }
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        ss.str("");
        ss.clear();
    }
    
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessLogs();
};

#endif	/* LOGS_H */