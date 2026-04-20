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

#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <list>
#include <vector>
#include <memory>
#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>

#include "scanners.h"
#include "supp.h"

int Scanners::GetConfig() {
       
    update_status = 1;
    return update_status;
}

int Scanners::Open(int mode, pid_t pid) {
    
    bool amq_conn = false;
    int conn_attempts = 0;
    
    p_pid = pid;
    
    do {
        try {
            if (connection == NULL) {
                
                activemq::library::ActiveMQCPP::initializeLibrary();
                
                // Create a ConnectionFactory
                string strUrl(url);
            
                unique_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(strUrl));
            
                // Create a Connection
                if (user_pwd) {
                    connection = connectionFactory->createConnection(user,pwd);
                } else {
                    connection = connectionFactory->createConnection();
                }
                
                connection->start();
            }
            
            if (session == NULL) {
                // Create a Session
                if (this->sessionTransacted) {
                    session = connection->createSession(Session::SESSION_TRANSACTED);
                } else {
                    session = connection->createSession(Session::AUTO_ACKNOWLEDGE);
                }
            }
            
            // Create the MessageConsumer
            string strConsumer("jms/altprobe/" + probe_name);
            
            Destination* consumerDest = session->createQueue(strConsumer);
            
            // Create a MessageConsumer from the Session to the Topic or Queue
            consumer = session->createConsumer(consumerDest);
 
            consumer->setMessageListener(this);
            
            mq_counter++;
        
            amq_conn = true;
            
            string log = "listens scanners bus";
            SysLog((char*) log.c_str());
 
        } catch (CMSException& e) {
        
            if (conn_attempts > 10) {
                SysLog("activeMQ operation error");
                string str = e.getMessage();
                const char * c = str.c_str();
                SysLog((char*) c);
                return 0;
            }
            sleep(3);
            conn_attempts++;
        }
        
    } while (!amq_conn);
    
    return 1;
}

int Scanners::Go(void) {
    
    sleep(1);
        
    return 1;
}

// Called from the consumer since this class is a registered MessageListener.
void Scanners::onMessage(const Message* message) {
    
    try {
        if (! dynamic_cast<const BytesMessage*> (message)) return;
                   
        string action_project_id = message->getStringProperty("project_id");
        if (!action_project_id.compare(project_id)) {
                        
            int action_type = message->getIntProperty("action_type");
            
            switch(action_type) {
                case 1: 
                    SetupPipeline(message);
                    break;
                case 2: 
                    TeardownPipeline();
                    break;
                case 3: 
                    if (SetupScan(message)) RunScan();
                    break;
                default: 
                    break;
            }
        }
    } catch (CMSException& e) { 
        SysLog((char*) e.what());
    }
    
    if (this->sessionTransacted) {
        session->commit();
    }
    
    CheckStatus();
}
 
// If something bad happens you see it here as this class is also been
// registered as an ExceptionListener with the connection.
void Scanners::onException(const CMSException& ex AMQCPP_UNUSED) {
    SysLog("activeMQ CMS exception occurred: scanners module");
    CheckStatus();
}

void Scanners::Close() {
    // Destroy resources.
    try {
        if (consumer) {
            delete consumer;
            consumer = NULL;
        }
        
        m_controller.lock();
        mq_counter--;
        m_controller.unlock();
        
        if (mq_counter == 0) {
            
            delete session;
            session = NULL;
            
            delete connection;
            connection = NULL;
        }
    } catch (CMSException& e) {
        SysLog("activeMQ operation error: destroy resources");
    }
}

void Scanners::SetupPipeline(const Message* message) {
    pipeline_name = message->getStringProperty("pipeline_name");
    pipeline_task  = message->getStringProperty("pipeline_task");
    SysLog("pipeline setup has been done");
}

void Scanners::TeardownPipeline() {
    pipeline_name = "indef";
    pipeline_task = "indef";
    SysLog("pipeline teardown has been done");
}

int Scanners::SetupScan(const Message* message) {
    int res;
    
    string action_c2 = message->getStringProperty("action_c2");
    SysLog((char*) action_c2.c_str());
        
    stringstream action_json_ss(action_c2);
    bpt::ptree pt;
    bpt::read_json(action_json_ss, pt);
    
    try {
        ClearWorkspace(path_workspace);
        
        last_test_time = GetProbeTime();
        
        // upload artifact_plugin
        string artifact_plugin =  pt.get<string>("args.artifact_plugin", "indef");
        string artifact_plugin_full_path = UploadPlugin(message, artifact_plugin);
        if (artifact_plugin_full_path.compare("indef") == 0) return 0;
        
        // make git_clone 
        string git_clone = pt.get<string>("args.git_clone", "indef");
        if (git_clone.compare("indef") != 0 && !git_clone.empty()) {
            int res = CloneRepo(git_clone);
            if (res == -1) return 0;
        } 
        
        // upload artifact_tests
        string artifact_tests =  pt.get<string>("args.artifact_tests", "indef");
        string artifact_tests_full_path = "indef";
        if (artifact_tests.compare("indef") != 0 && !artifact_tests.empty()) {
            artifact_tests_full_path = UploadTests(message, artifact_tests);
            if (artifact_tests_full_path.compare("indef") == 0) return 0;
        }
        
        string output_file = pt.get<string>("args.output_file", "indef");
        output_file_full_path = CombinePaths(path_output, output_file);
        
        test.Reset();
        test.pipeline_name = message->getStringProperty("pipeline_name");
        test.pipeline_task  = message->getStringProperty("pipeline_task");
        test.test_type = pt.get<string>("args.test_type", "indef");
        test.test_corr = pt.get<string>("args.test_corr", "indef");
        test.job_name = pt.get<string>("args.job_name", "indef");
        test.asset_name = pt.get<string>("args.asset_name", "indef");
        test.asset_target = pt.get<string>("args.asset_target", "indef");
        test.output_format = pt.get<string>("args.output_format", "indef");
        
        
        // Parameters:
        // $0 - full path to artifact_plugin (with path_workspace)
        // $1 - path_workspace
        // $2 - artifact_tests
        // $3 - full path to artifact_tests (with path_workspace)
        // $4 - path_output
        // $5 - output_file
        // $6 - full path to output_file (with path_output)
        // $7 - target
        // $8 - run_mode
        
        string run_mode;
        if (is_docker) run_mode= "docker";
        else run_mode = "host";
        
        cmd = artifact_plugin_full_path + 
            " " + 
            path_workspace +
            " " +
            artifact_tests +
            " " +
            artifact_tests_full_path + 
            " " + 
            path_output +
            " " +
            output_file + 
            " " +
            output_file_full_path + 
            " " + 
            test.asset_target +
            " " +
            run_mode;
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return 0;
    } 
    
    SysLog("test setup has been done)");
    return 1;
}

void Scanners::RunScan() {
    int res;
    try {
        
        SysLog((char*) cmd.c_str());
        
        int res = system(cmd.c_str());
        
        if (res != 0) {
            string error_code = "test script return error: " + std::to_string(res);
            SysLog((char*) error_code.c_str());
            return;
        }
        
        std::ifstream output_report;
        
        output_report.open(output_file_full_path, ios::binary);
        strStream << output_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        test.data = comp.str();
        boost::iostreams::close(in);
        
        SendMessage(&test);
        
        SysLog("scan results has been sent");
                
        output_report.close();
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
}

string Scanners::UploadTests(const Message* message, const string& artifact_tests) {
    
    string artifact_tests_full_path = "";
    
    try { 
    
        const BytesMessage* bytesMessage = dynamic_cast<const BytesMessage*> (message);
    
        const unsigned char* comp = bytesMessage->getBodyBytes();
        int comp_size = bytesMessage->getBodyLength();
    
        stringstream ss, decomp;
    
        ss.write(reinterpret_cast<const char*>(&comp[0]),comp_size);
    
        boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
        inbuf.push(boost::iostreams::gzip_decompressor());
        inbuf.push(ss);
        boost::iostreams::copy(inbuf, decomp);
        boost::iostreams::close(inbuf);
    
        ofstream ostream;
    
        artifact_tests_full_path = CombinePaths(path_workspace, artifact_tests);
        
        ostream.open(artifact_tests_full_path, ios_base::trunc);
        ostream << decomp.str();
        ostream.close();
    
    } catch (std::ostream::failure e) {
        SysLog("exception for template file.");
        return "indef";
    }
    
    SysLog("artifact tests has been loaded");
    return artifact_tests_full_path;
}

string Scanners::UploadPlugin(const Message* message, const string& artifact_plugin) {
    
    string artifact_plugin_full_path = "";
    
    try { 
        
        artifact_plugin_full_path = CombinePaths(path_workspace, artifact_plugin);
        
        int fd = open(artifact_plugin_full_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
        
         if (fd == -1) {
            SysLog("error create plugin file");
            return "indef";
        }
        
        string plugin_content = message->getStringProperty("artifact_plugin");
        
        write(fd, plugin_content.c_str(), plugin_content.size());
        close(fd);
        
        chmod(artifact_plugin_full_path.c_str(), 755);  // u+rwx
    } catch (std::ostream::failure e) {
        SysLog("exception for template file.");
        return "indef";
    }
    
    SysLog("artifact has been loaded");
    return artifact_plugin_full_path;
}

int Scanners::CloneRepo(const string& git_clone) {
    
    chdir((char*) path_workspace.c_str());
    string cmd = "git -c http.sslVerify=false clone " + git_clone;
    SysLog((char*) cmd.c_str());
    int res = system(cmd.c_str());
    
    if (res == -1) {
        SysLog("error cloning repo");
        return -1;
    }
    
    return 0;
}





