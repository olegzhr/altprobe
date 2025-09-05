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

#include "config.h"

void ConfigYaml::ParsConfig() {
    
    do {
        yaml_parser_scan(&parser, &token);
        switch(token.type)
        {
            /* Token types (read before actual token) */
            case YAML_KEY_TOKEN:   
                state_key = 1; 
                break;
            case YAML_VALUE_TOKEN: 
                state_key = 0; 
                break;
            /* Block delimeters */
            case YAML_BLOCK_END_TOKEN:
                if (state_map > 1) {
                    state_map--;
                    state_key = 1;
                    if (state == 1) state = 0;
                }
                break;
            /* Data */
            case YAML_BLOCK_MAPPING_START_TOKEN:
                if (state_map != 0) state_map = 2;
                else state_map = 1;
                break;
            case YAML_SCALAR_TOKEN:
                if (state_map < 2) {
                    if (!strcmp ((char*) token.data.scalar.value, scalar_token.c_str()))
                        state = 1;
                }
                else {
                    if (!state_key) {
                        if (state == 1) {
                            map <string, Parameters*>::iterator i;
                            Parameters* ptr;
                            
                            for(i = config.begin(); i != config.end(); ++i) {
                                
                                ptr = (Parameters*) (*i).second;
                                
                                if (ptr->flag) {
                                    string value((char*) token.data.scalar.value);
                                    ptr->parameter = value;
                                    ptr->flag =false;
                                    break;
                                }
                            }
                        }
                    }    
                    else {
                        if (state == 1) {
                            string key((char*) token.data.scalar.value);
                            if (testKey(key)) setFlag(key, true);
                        }
                    }
                }    
                break;
                /* Others */
        }
        
        if(token.type != YAML_STREAM_END_TOKEN)
            yaml_token_delete(&token);
    } while(token.type != YAML_STREAM_END_TOKEN);
}
