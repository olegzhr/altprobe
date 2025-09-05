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

#include "sinks.h"

bool Sinks::sinks_config_flag = false;

int Sinks::GetConfig() {
    
    if (!sinks_config_flag) {
        sinks_config_flag = true; 
        
        if (!CObject::GetConfig()) return 0; 
        
        int ctrl_state = ctrl.GetConfig();
        if(ctrl_state == 0) return 0;
    }
        
    return 1;
}

int Sinks::Open() {
    if(!ctrl.Open()) return 0;
    
    return 1;
}

void Sinks::Close() {
    ctrl.Close();
}

int Sinks::SendMessage(Event* e) { 
    if (!ctrl.SendMessage(e)) {
       return 0;
    }
    return 1;
}

void Sinks::SendAlert(void) {
    alert.CreateAlertUUID();
    ctrl.SendMessage(&alert);
    alert.Reset();
}







