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
 
#include <mutex>
#include <activemq-cpp-3.9.5/cms/Message.h>

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include "controller.h"

int Controller::mq_counter = 0;
mutex Controller::m_controller;

bool Controller::ctrl_config_flag = false;

Connection* Controller::connection = NULL;
Session* Controller::session;
Destination* Controller::destMonitor;
MessageProducer* Controller::producerMonitor;
Destination* Controller::destLog;
MessageProducer* Controller::producerLog;
Destination* Controller::destTest;
MessageProducer* Controller::producerTest;
Destination* Controller::destStatus;
MessageProducer* Controller::producerStatus;
bool Controller::sessionTransacted = false;

int Controller::connection_error = 0;
int Controller::controller_mode = 1;
pid_t Controller::p_pid = 0;

int Controller::GetConfig() {
    
    if (!ctrl_config_flag) {
        ctrl_config_flag = true; 
    }
    
    return 1;
}

void Controller::CheckStatus() {
    
    connection_error++;
    
    if (connection_error > 100) {
        if (controller_mode == 1) {
            if (daemon_pid_file_kill_wait(SIGTERM, 5) < 0)
                // daemon_log(LOG_ERR, "Failed to kill AlertFlex collector: %s.", strerror(errno));
                SysLog( "Failed to kill alertflex controller module.");
                // else daemon_log(LOG_ERR, "AlertFlex collector is stopping.");
            else SysLog( "Alertflex collector is stopping, controller module.");
        } else {
            kill(p_pid, SIGTERM); 
            SysLog( "Alertflex collector is stopping, controller module.");
        }
    }
}

int Controller::Open() {
    
    bool amq_conn = false;
    int conn_attempts = 0;
    
    do {
        try {
            if (connection == NULL) {
                
                activemq::library::ActiveMQCPP::initializeLibrary();
                
                // Create a ConnectionFactory
                auto_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(url));
            
                // Create a Connection
                if (user_pwd) {
                    connection = connectionFactory->createConnection(user.c_str(), pwd.c_str());
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
            
            if (producerMonitor == NULL) {
            
                // Create the destination for alerts
                string strAlert("jms/alertflex/monitor");
            
                destMonitor = session->createQueue(strAlert);
                        
                // Create a MessageProducer from the Session to Queue
                producerMonitor = session->createProducer(destMonitor);
       
                producerMonitor->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
            
            if (producerLog == NULL) {
            
                // Create the destination for statistics(Queue)
                string strLog("jms/alertflex/log");
            
                destLog = session->createQueue(strLog);
                        
                // Create a MessageProducer from the Session to Queue
                producerLog = session->createProducer(destLog);
       
                producerLog->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
            
            if (producerTest == NULL) {
            
                // Create the destination for statistics(Queue)
                string strTest("jms/alertflex/test");
            
                destTest = session->createQueue(strTest);
                        
                // Create a MessageProducer from the Session to Queue
                producerTest = session->createProducer(destTest);
       
                producerTest->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
            
            if (producerStatus == NULL) {
            
                // Create the destination for statistics(Queue)
                string strStatus("jms/alertflex/status");
            
                destStatus = session->createQueue(strStatus);
                        
                // Create a MessageProducer from the Session to Queue
                producerStatus = session->createProducer(destStatus);
       
                producerStatus->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
            
            mq_counter++;
        
            amq_conn = true;
                 
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

int Controller::SendMessage(Event* e) {
    
    event_types msg_type = e->et;
    
    try {
        
        switch (msg_type) {
            
            case ALERT: {
                auto_ptr<TextMessage> message(session->createTextMessage());
                
                message->setIntProperty("msg_type", ALERT);
                message->setStringProperty("project_id", project_id);
                message->setStringProperty("probe_name", probe_name);
                message->setStringProperty("sensors_group", sensors_group);
                message->setStringProperty("pipeline_name", pipeline_name);
                message->setStringProperty("pipeline_task", pipeline_task);
                string strAlertUuid(((Alert*) e)->alert_uuid);
                message->setStringProperty("alert_uuid", strAlertUuid);
                string strAlertSeverity(((Alert*) e)->alert_severity);
                message->setStringProperty("alert_severity", strAlertSeverity);
                string strAlertSource(((Alert*) e)->alert_source);
                message->setStringProperty("alert_source", strAlertSource);
                string strAlertRule(((Alert*) e)->alert_rule);
                message->setStringProperty("alert_rule", strAlertRule);
                string strAlertMessage(((Alert*) e)->alert_message);
                message->setStringProperty("alert_message", strAlertMessage);
                string strSrcIp(((Alert*) e)->src_ip);
                message->setStringProperty("src_ip", strSrcIp);
                message->setIntProperty("src_port", ((Alert*) e)->src_port);
                string strDstIp(((Alert*) e)->dst_ip);
                message->setStringProperty("dst_ip", strDstIp);
                message->setIntProperty("dst_port", ((Alert*) e)->dst_port);
                string strFileName(((Alert*) e)->file_name);
                message->setStringProperty("file_name", strFileName);
                string strUserName(((Alert*) e)->user_name);
                message->setStringProperty("user_name", strUserName);
                message->setIntProperty("process_id", ((Alert*) e)->process_id);
                string strProcessName(((Alert*) e)->process_name);
                message->setStringProperty("process_name", strProcessName);
                string strContainerId(((Alert*) e)->container_id);
                message->setStringProperty("container_id", strContainerId);
                string strContainerName(((Alert*) e)->container_name);
                message->setStringProperty("container_name", strContainerName);
                string strNameSpace(((Alert*) e)->name_space);
                message->setStringProperty("name_space", strNameSpace);
                string strPodId(((Alert*) e)->pod_id);
                message->setStringProperty("pod_id", strPodId);
                string strPodName(((Alert*) e)->pod_name);
                message->setStringProperty("pod_name", strPodName);
                
                message->setLongProperty("http_flowid", ((Alert*) e)->http_flowid);
                string strHttpHostname(((Alert*) e)->http_hostname);
                message->setStringProperty("http_hostname", strHttpHostname);
                message->setIntProperty("http_port", ((Alert*) e)->http_port);
                string strHttpUrl(((Alert*) e)->http_url);
                message->setStringProperty("http_url", strHttpUrl);
                string strHttpMethod(((Alert*) e)->http_method);
                message->setStringProperty("http_method", strHttpMethod);
                string strHttpContentType(((Alert*) e)->http_content_type);
                message->setStringProperty("http_content_type", strHttpContentType);
                string strHttpRequestBody(((Alert*) e)->http_request_body);
                message->setStringProperty("http_request_body", strHttpRequestBody);
                message->setIntProperty("http_status", ((Alert*) e)->http_status);
                
                string strOriginalTime(((Alert*) e)->original_time);
                message->setStringProperty("original_time", strOriginalTime);
                           
                producerMonitor->send(message.get());
                break;
            }
            
            case LOG: {
                BytesMessage* byte_message = session->createBytesMessage();
            
                byte_message->setIntProperty("msg_type", msg_type);
                byte_message->setStringProperty("project_id", project_id);
                byte_message->setStringProperty("probe_name", probe_name);
                byte_message->setStringProperty("sensors_group", sensors_group);
                byte_message->setStringProperty("pipeline_name", pipeline_name);
                byte_message->setStringProperty("pipeline_task", pipeline_task);
                                
                vector<unsigned char> vec;
                string msg_comp = ((ByteData*) e)->data;
                const char* c = msg_comp.c_str();
                for (int i=0; i < msg_comp.size() + 1; i++) vec.push_back(c[i]);
                
                byte_message->writeBytes(vec);
            
                producerLog->send(byte_message);
                delete byte_message;
                break;
            }
            
            case TEST: {
                BytesMessage* byte_message = session->createBytesMessage();
                
                byte_message->setIntProperty("msg_type", msg_type);
                byte_message->setStringProperty("project_id", project_id);
                byte_message->setStringProperty("probe_name", probe_name);
                string strPipelineName(((Test*) e)->pipeline_name);
                byte_message->setStringProperty("pipeline_name", strPipelineName);
                string strPipelineTask(((Test*) e)->pipeline_task);
                byte_message->setStringProperty("pipeline_task", strPipelineTask);
                string strTestType(((Test*) e)->test_type);
                byte_message->setStringProperty("test_type", strTestType);
                string strTestCorr(((Test*) e)->test_corr);
                byte_message->setStringProperty("test_corr", strTestCorr);
                string strJobName(((Test*) e)->job_name);
                byte_message->setStringProperty("job_name", strJobName);
                string strAssetName(((Test*) e)->asset_name);
                byte_message->setStringProperty("asset_name", strAssetName);
                string strAssetTarget(((Test*) e)->asset_target);
                byte_message->setStringProperty("asset_target", strAssetTarget);
                string strOutputFormat(((Test*) e)->output_format);
                byte_message->setStringProperty("output_format", strOutputFormat);
                                                
                vector<unsigned char> vec;
                string msg_comp = ((ByteData*) e)->data;
                const char* c = msg_comp.c_str();
                for (int i=0; i < msg_comp.size() + 1; i++) vec.push_back(c[i]);
                
                byte_message->writeBytes(vec);
            
                producerTest->send(byte_message);
                delete byte_message;
                break;
            }
            
            case STATUS: {
                BytesMessage* byte_message = session->createBytesMessage();
            
                byte_message->setIntProperty("msg_type", msg_type);
                byte_message->setStringProperty("project_id", project_id);
                byte_message->setStringProperty("probe_name", probe_name);
                byte_message->setStringProperty("sensors_group", sensors_group);
                byte_message->setStringProperty("pipeline_name", pipeline_name);
                byte_message->setStringProperty("pipeline_task", pipeline_task);
                                
                vector<unsigned char> vec;
                string msg_comp = ((ByteData*) e)->data;
                const char* c = msg_comp.c_str();
                for (int i=0; i < msg_comp.size() + 1; i++) vec.push_back(c[i]);
                
                byte_message->writeBytes(vec);
            
                producerStatus->send(byte_message);
                delete byte_message;
                break;
            }
        }
    } catch (CMSException& e) {
        SysLog("ActiveMQ CMS Exception occurred.");
        CheckStatus();
        return 0;
    }
        
    return 1;
}

void Controller::Close() {
 
    if (connection != NULL) {
        try {
            connection->close();
            
        } catch (cms::CMSException& ex) {
            SysLog("activeMQ operation error: connection close");
        }
    }
 
    // Destroy resources.
    try {
        delete destMonitor;
        destMonitor = NULL;
        
        if (producerMonitor) {
            delete producerMonitor;
            producerMonitor = NULL;
        }
        
        delete destLog;
        destLog = NULL;
        
        if (producerLog) {
            delete producerLog;
            producerLog = NULL;
        }
        
        delete destTest;
        destTest = NULL;
        
        if (producerTest) {
            delete producerTest;
            producerTest = NULL;
        }
        
        delete destStatus;
        destStatus = NULL;
        
        if (producerStatus) {
            delete producerStatus;
            producerStatus = NULL;
        }
        
        delete session;
        session = NULL;
        
        m_controller.lock();
        mq_counter--;
        m_controller.unlock();
        
        if (mq_counter == 0) {
            delete connection;
            connection = NULL;
        }
        
    } catch (CMSException& e) {
        SysLog("activeMQ operation error: destroy resources");
    }
}




