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

#include "source.h"

int Source::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    if (!redis_host.compare("indef") || redis_port == 0) {
    
        redis_status = false;
       
    } else {
        
        is_docker = IsRunningInDockerContainer();
        
        if (is_docker) {
            const char* env_val = nullptr;
            env_val = getenv(env_key.c_str());
            redis_key = env_val ? env_val : "indef";
            
        } else {
            ConfigYaml* cy = new ConfigYaml("sensors");
            
            cy->addKey(config_key);
            
            cy->ParsConfig();
    
            redis_key = cy->getParameter(config_key);
        }
        
        if (!redis_key.compare("indef")) redis_status = false;
        else redis_key = "lpop " + redis_key;
        
        if (!config_key.compare("app_redis")) app_redis_status = redis_status;
        if (!config_key.compare("falco_redis")) falco_redis_status = redis_status;
        if (!config_key.compare("suricata_redis")) suricata_redis_status = redis_status;
    }
    
    return 1;
}