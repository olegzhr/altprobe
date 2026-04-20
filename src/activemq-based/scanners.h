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

#ifndef SCANNERS_H
#define	SCANNERS_H

#include <boost/asio.hpp>
#include "base64.h"
#include "controller.h"
#include "workspace.h"

namespace bpt = boost::property_tree;
using namespace std;

class Scanners : public Controller,
        public ExceptionListener,
        public MessageListener {
public: 
    
    Destination* consumerDest;
    MessageConsumer* consumer;
    int update_status;
    
    string cmd;
    string output_file_full_path;
    
    Test test;
    
    std::stringstream strStream, comp;
    
    Scanners() {
        consumer = NULL;
        update_status = 0;
    }
        
    virtual int Open(int mode, pid_t pid);
    virtual void Close();
    virtual int GetConfig();
    int GetStatus() {
        return update_status;
    }
    
    int Go();
    void onMessage(const Message* message);
    void onException(const CMSException& ex AMQCPP_UNUSED);
    
    int SetupScan(const Message* message);
    void RunScan();
    string UploadTests(const Message* message, const string& artifact_tests);
    string UploadPlugin(const Message* message, const string& artifact_plugin);
    int CloneRepo(const string& git_clone);
    void SetupPipeline(const Message* message);
    void TeardownPipeline();
    
    void ResetStreams() {
        cmd.clear();
        output_file_full_path.clear();
        comp.str("");
        comp.clear();
        strStream.str("");
        strStream.clear();
    }
};

#endif	/* SCANNERS_H */

