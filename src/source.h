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

#ifndef SOURCE_H
#define	SOURCE_H

#include <mutex>

#include "hiredis.h"
#include "sinks.h"
#include "config.h"

using namespace std;

class Source : public CObject {
public:
    bool source_status;
    bool redis_status;
    string redis_key;
    string config_key;
    string env_key;
    
    redisReply *reply;
    redisContext *c;
    
    string json_report;
        
    // interfaces
    Sinks sk;
    
    Source () {
        source_status = true;
        redis_status = false;
    }
        
    Source (string ckey, string ekey) {
        source_status = true;
        redis_status = true;
        config_key = ckey;
        env_key = ekey;
    }
    
    virtual int GetConfig();
    
    virtual int GetStatus() {
        return source_status;
    }
};

#endif	/* SOURCE_H */