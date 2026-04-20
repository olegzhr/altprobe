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

#ifndef CONTROLLER_H
#define	CONTROLLER_H

#include <mutex>
#include <activemq/library/ActiveMQCPP.h>
#include <decaf/lang/Thread.h>
#include <decaf/lang/Runnable.h>
#include <decaf/lang/Integer.h>
#include <decaf/lang/Long.h>
#include <decaf/lang/System.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/util/Config.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/TextMessage.h>
#include <cms/BytesMessage.h>
#include <cms/MapMessage.h>
#include <cms/ExceptionListener.h>
#include <cms/MessageListener.h>

#include "cobject.h"

using namespace activemq::core;
using namespace decaf::util::concurrent;
using namespace decaf::util;
using namespace decaf::lang;
using namespace cms;
using namespace std;

class Controller : public CObject {
public:
    static bool ctrl_config_flag;
    
    static int mq_counter;
    static mutex m_controller;
    
    static Connection* connection;
    static Session* session;
    static Destination* destMonitor;
    static MessageProducer* producerMonitor;
    static Destination* destLog;
    static MessageProducer* producerLog;
    static Destination* destTest;
    static MessageProducer* producerTest;
    static Destination* destStatus;
    static MessageProducer* producerStatus;
    static bool sessionTransacted;
    
    static int connection_error;
    static int controller_mode;
    static pid_t p_pid;
    
    Controller () {
        session = NULL;
        destMonitor = NULL;
        producerMonitor = NULL;
        destLog = NULL;
        producerLog = NULL;
        destTest = NULL;
        producerTest = NULL;
        destStatus = NULL;
        producerStatus = NULL;
    }
     
    virtual int Open();
    virtual int GetConfig();
    void CheckStatus();
    int SendMessage(Event* e);
    virtual void Close();
};

#endif	/* CONTROLLER_H */

