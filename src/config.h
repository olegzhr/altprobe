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

#ifndef CONFIG_H
#define	CONFIG_H

#include "main.h"

using namespace std;

class Parameters {
public:
    string parameter;
    bool flag;
    
    Parameters() {
        this->parameter = "";
        this->flag = false;
    }
};

class ConfigYaml {
public:
    FILE *fh;
    yaml_parser_t parser;
    yaml_token_t token;

    int init;
    int state_map;
    int state_key;
    int state;

    string scalar_token;
    map <string, Parameters*> config;

    ConfigYaml(string st) {

        scalar_token = st;

        state_map = 0;
        state_key = 0;
        state = 0;
        
        fh = fopen(CONFIG_FILE, "r");
        if (!fh) {
            init = 0;
            return;
        }

        /* Initialize parser */
        if (!yaml_parser_initialize(&parser)) {
            init = 0;
            return;
        }

        /* Set input file */
        yaml_parser_set_input_file(&parser, fh);
        init = 1;
    }

    ~ConfigYaml() {
        /* Cleanup */
        yaml_token_delete(&token);
        yaml_parser_delete(&parser);
        fclose(fh);
    }

    int GetInitStatus() {
        return init;
    }
    
    void addKey(string key) {
        Parameters* p = new Parameters();
        config.insert(make_pair(key, p));
    }
    
    bool testKey(string key) {
        if (config.find(key) == config.end()) return false;
        return true;
    }
    
    void setParameter(string key, string p) {
        Parameters* ptr = (Parameters*) config[key];
        ptr->parameter = p;
    }
    
    void setFlag(string key, bool f) {
        Parameters* ptr = (Parameters*) config[key];
        ptr->flag = f;
    }
    
    string getParameter(string key) {
        Parameters* ptr = (Parameters*) config[key];
        return ptr->parameter;
    }
    
    bool getFlag(string key) {
        Parameters* ptr = (Parameters*) config[key];
        return ptr->flag;
    }
    
    void ParsConfig();
};

#endif	/* CONFIG_H */