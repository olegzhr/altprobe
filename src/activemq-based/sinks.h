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

#ifndef SINKS_H
#define	SINKS_H

#include "controller.h"
#include "config.h"

class Sinks : public CObject {
public:
    static bool sinks_config_flag;
    
    // Controller operations
    Controller ctrl;
    
    Alert alert;
    
    void Init() {
        alert.Reset();
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig();
    
    int SendMessage(Event* e);
    //Send Alert to Controller
    void SendAlert(void);
    
};

#endif	/* SINKS_H */

