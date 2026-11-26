/*
 *   Copyright 2021-2026 Oleg Zharkov
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
#define CONFIG_H

#include <yaml-cpp/yaml.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include "main.h"

class YamlConfig {
private:
    YAML::Node root;
    std::string filename;
    
public:
    YamlConfig(const std::string& config_file = CONFIG_FILE) : filename(config_file) {
        try {
            root = YAML::LoadFile(filename);
        } catch (const YAML::Exception& e) {
            std::cerr << "Error loading config file '" << filename << "': " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Unknown error loading config file '" << filename << "'" << std::endl;
        }
    }
    
    // Get string value with default
    std::string getString(const std::string& section, const std::string& key, 
                          const std::string& default_value = "") {
        try {
            if (root[section] && root[section][key]) {
                return root[section][key].as<std::string>();
            }
        } catch (const YAML::Exception& e) {
            std::cerr << "Error reading '" << section << "." << key << "': " << e.what() << std::endl;
        }
        return default_value;
    }
    
    // Get a scalar or YAML sequence as a comma-separated list.
    std::vector<std::string> getStringList(const std::string& section, const std::string& key,
                                          const std::string& default_value = "") {
        std::vector<std::string> values;
        try {
            if (root[section] && root[section][key]) {
                const auto& node = root[section][key];
                if (node.IsSequence()) {
                    for (const auto& item : node) values.push_back(item.as<std::string>());
                } else {
                    std::stringstream stream(node.as<std::string>()); std::string part;
                    while (std::getline(stream, part, ',')) values.push_back(part);
                }
                return values;
            }
        } catch (const YAML::Exception& e) {
            std::cerr << "Error reading '" << section << "." << key << "': " << e.what() << std::endl;
        }
        std::stringstream stream(default_value); std::string part;
        while (std::getline(stream, part, ',')) values.push_back(part);
        return values;
    }

    int getIntStrict(const std::string& section, const std::string& key, int default_value) {
        if (!root[section] || !root[section][key]) return default_value;
        return root[section][key].as<int>();
    }

    // Get integer value with default
    int getInt(const std::string& section, const std::string& key, int default_value = 0) {
        try {
            if (root[section] && root[section][key]) {
                return root[section][key].as<int>();
            }
        } catch (const YAML::Exception& e) {
            std::cerr << "Error reading '" << section << "." << key << "': " << e.what() << std::endl;
        }
        return default_value;
    }
    
    // Get boolean value from string ("true"/"false")
    bool getBool(const std::string& section, const std::string& key, bool default_value = false) {
        try {
            if (root[section] && root[section][key]) {
                std::string value = root[section][key].as<std::string>();
                return (value == "true" || value == "yes" || value == "1");
            }
        } catch (const YAML::Exception& e) {
            std::cerr << "Error reading '" << section << "." << key << "': " << e.what() << std::endl;
        }
        return default_value;
    }
    // Security switches must reject malformed values instead of using a permissive default.
    bool getBoolStrict(const std::string& section, const std::string& key, bool default_value = false) {
        if (!root[section] || !root[section][key]) return default_value;
        return root[section][key].as<bool>();
    }

    // sinks.alertflex holds Alertflex-specific delivery settings.
    std::string getAlertflexString(const std::string& key, const std::string& default_value = "") {
        try {
            YAML::Node alertflex = root["sinks"]["alertflex"];
            if (alertflex && alertflex[key]) return alertflex[key].as<std::string>();
        } catch (const YAML::Exception& e) {
            std::cerr << "Error reading 'sinks.alertflex." << key << "': " << e.what() << std::endl;
        }
        return default_value;
    }

    // Check if config was loaded successfully
    bool isValid() const {
        return root.IsDefined() && root.IsMap();
    }
};

#endif /* CONFIG_H */
