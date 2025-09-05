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

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <sstream>

#include "workspace.h"
#include "cobject.h"

bool CObject::cobject_config_flag = false;

// collector
string CObject::project_id;
string CObject::probe_name;
string CObject::sensors_group;

bool CObject::is_docker;

int CObject::timezone_offset = 0;
int CObject::report_interval = 0;

// controller
string CObject::url;
string CObject::user;
string CObject::pwd;
bool CObject::user_pwd = true;

bool CObject::enable_alerts = true;
bool CObject::enable_logs = true;

// scanners
string CObject::path_workspace;
string CObject::path_output;

// sensors
string CObject::app_log;
bool CObject::app_log_status = true;
bool CObject::app_redis_status = false;
string CObject::falco_log; 
bool CObject::falco_log_status = true;
bool CObject::falco_redis_status = false;
string CObject::suricata_log; 
bool CObject::suricata_log_status = true;
bool CObject::suricata_redis_status = false;
string CObject::redis_host;
int CObject::redis_port = 6379;

// extra non config parameters
char CObject::sys_log_info[OS_LONG_HEADER_SIZE];
int CObject::gosleep_interval = 1000;

string CObject::pipeline_name = "indef"; 
string CObject::pipeline_task = "indef";
string CObject::last_test_time = "indef";

int CObject::GetConfig() {
    
    ConfigYaml* cy;
    
    if (!cobject_config_flag) {
        cobject_config_flag = true; 
        
        is_docker = IsRunningInDockerContainer();
        
        if (is_docker) {
        
            // Try to get from environment variables first
            const char* env_val = nullptr;
        
            // get collector parameters
            env_val = getenv("ALTPROBE_PROJECT_ID");
            project_id = env_val ? env_val : "";
        
            env_val = getenv("ALTPROBE_PROBE_NAME");
            probe_name = env_val ? env_val : "";
        
            env_val = getenv("ALTPROBE_SENSORS_GROUP");
            sensors_group = env_val ? env_val : "";
        
            env_val = getenv("ALTPROBE_TIMEZONE_OFFSET");
            timezone_offset = env_val ? stoi(env_val) : 0;
        
            env_val = getenv("ALTPROBE_REPORT_INTERVAL");
            report_interval = env_val ? stoi(env_val) : 0;
            
            if (project_id.empty()) {
                SysLog("config error: parameter project id (env:ALTPROBE_PROJECT_ID)");
                return 0;
            }
        
            if (probe_name.empty()) {
                SysLog("config error: parameter probe_name (env:ALTPROBE_PROBE_NAME)");
                return 0;
            }
        
            if (sensors_group.empty()) {
                SysLog("config error: parameter sensors_group (env:ALTPROBE_SENSORS_GROUP)");
                return 0;
            }
            
            //get controller parameters from env
            env_val = getenv("CONTROLLER_URL");
            url = env_val ? env_val : "";
        
            env_val = getenv("CONTROLLER_USER");
            user = env_val ? env_val : "";
        
            env_val = getenv("CONTROLLER_PWD");
            pwd = env_val ? env_val : "";
        
            env_val = getenv("CONTROLLER_ENABLE_ALERTS");
            enable_alerts = env_val ? (strcmp(env_val, "true") == 0) : true;
        
            env_val = getenv("CONTROLLER_ENABLE_LOGS");
            enable_logs = env_val ? (strcmp(env_val, "true") == 0) : true;
            
            if (url.empty()) {
                SysLog("config error: parameter controller url (env:CONTROLLER_URL)");
                return 0;
            }
            
            if (user.empty() && pwd.empty()) user_pwd = false;
            else {
                if (user.empty()) {
                    SysLog("config error: parameter controller user (env:CONTROLLER_USER)");
                    return 0;
                }
        
                if (pwd.empty()) {
                    SysLog("config error: parameter controller pwd (env:CONTROLLER_PWD)");
                    return 0;
                }
            }
            
            // get scanner parameters from env
            env_val = getenv("SCANNERS_WORKSPACE");
            path_workspace = env_val ? env_val : "";
            
            if (path_workspace.empty()) {
                SysLog("config error: work_space not set (env:SENSORS_WORKSPACE)");
                return 0;
            }
            
            EnsureTrailingSlash(path_workspace);
        
            if (!IsDirectory(path_workspace)) {
                SysLog("config error: sensors workspace is not directory");
                return 0;
            }
        
            if (!IsWritableDirectory(path_workspace)) {
                SysLog("config error: sensors workspace has not write permissions");
                return 0;
            }
        
            if (!IsDirectoryEmpty(path_workspace)) {
                ClearWorkspace(path_workspace);
            }
            
            // get scanner parameters from env
            env_val = getenv("SCANNERS_OUTPUT");
            path_output = env_val ? env_val : "";
            
            if (path_output.empty()) {
                SysLog("config error: sensors output not set (env:SENSORS_OUTPUT)");
                return 0;
            }
            
            EnsureTrailingSlash(path_output);
        
            if (!IsDirectory(path_output)) {
                SysLog("config error: sensors output is not directory");
                return 0;
            }
        
            if (!IsWritableDirectory(path_output)) {
                SysLog("config error: sensors output has not write permissions");
                return 0;
            }
        
            if (!IsDirectoryEmpty(path_output)) {
                ClearWorkspace(path_output);
            }
        
            // get sensors parameters from env
            env_val = getenv("SENSORS_APP_LOG");
            app_log = env_val ? env_val : "indef";
            app_log_status = (app_log != "indef");
            
            env_val = getenv("SENSORS_FALCO_LOG");
            falco_log = env_val ? env_val : "indef";
            falco_log_status = (falco_log != "indef");
        
            env_val = getenv("SENSORS_SURICATA_LOG");
            suricata_log = env_val ? env_val : "indef";
            suricata_log_status = (suricata_log != "indef");
            
            app_log_status = (app_log != "indef");
            falco_log_status = (falco_log != "indef");
            suricata_log_status = (suricata_log != "indef");
        
            env_val = getenv("SENSORS_REDIS_HOST");
            redis_host = env_val ? env_val : "";
        
            env_val = getenv("SENSORS_REDIS_PORT");
            redis_port = env_val ? stoi(env_val) : 6379;
            
        }  else {   
            
            cy = new ConfigYaml("altprobe");
            cy->addKey("project_id");
            cy->addKey("probe_name");
            cy->addKey("sensors_group");
            cy->addKey("timezone_offset");
            cy->addKey("report_interval");
            cy->ParsConfig();
            
            project_id = cy->getParameter("project_id");
            probe_name = cy->getParameter("probe_name");
            sensors_group = cy->getParameter("sensors_group");
            timezone_offset = stoi(cy->getParameter("timezone_offset"));
            report_interval = stoi(cy->getParameter("report_interval"));
        
            if (project_id.empty()) {
                SysLog("config error: parameter project id");
                return 0;
            }
        
            if (probe_name.empty()) {
                SysLog("config error: parameter probe_name");
                return 0;
            }
        
            if (sensors_group.empty()) {
                SysLog("config error: parameter sensors_group");
                return 0;
            }
        
            // Fallback to config file if needed
            cy = new ConfigYaml("controller");
            cy->addKey("url");
            cy->addKey("user");
            cy->addKey("pwd");
            cy->addKey("enable_alerts");
            cy->addKey("enable_logs");
            cy->ParsConfig();
            
            url = cy->getParameter("url");
            user = cy->getParameter("user");
            pwd = cy->getParameter("pwd");
            
            string enable_alerts_str = cy->getParameter("enable_alerts");
            if (enable_alerts_str.compare("true")) enable_alerts = false;
            
            string enable_logs_str = cy->getParameter("enable_logs");
            if (enable_logs_str.compare("true")) enable_logs = false;
        
            if (url.empty()) {
                SysLog("config error: parameter controller url");
                return 0;
            }
            
            if (user.empty() && pwd.empty()) user_pwd = false;
            else {
                if (user.empty()) {
                    SysLog("config error: parameter controller user");
                    return 0;
                }
        
                if (pwd.empty()) {
                    SysLog("config error: parameter controller pwd");
                    return 0;
                }
            }
        
            cy = new ConfigYaml("scanners");
            cy->addKey("workspace");
            cy->addKey("output");
            cy->ParsConfig();
            
            path_workspace = cy->getParameter("workspace");
            
            if (path_workspace.empty()) {
                SysLog("config error: workspace not set");
                return 0;
            }
        
            if (!IsDirectory(path_workspace)) {
                SysLog("config error: workspace is not directory");
                return 0;
            }
        
            if (!IsWritableDirectory(path_workspace)) {
                SysLog("config error: workspace has not write permissions");
                return 0;
            }
        
            if (!IsDirectoryEmpty(path_workspace)) {
                ClearWorkspace(path_workspace);
            }
        
            EnsureTrailingSlash(path_workspace);
            
            path_output = cy->getParameter("output");
            
            if (path_workspace.empty()) {
                SysLog("config error: output not set");
                return 0;
            }
        
            if (!IsDirectory(path_output)) {
                SysLog("config error: output is not directory");
                return 0;
            }
        
            if (!IsWritableDirectory(path_output)) {
                SysLog("config error: output has not write permissions");
                return 0;
            }
        
            if (!IsDirectoryEmpty(path_output)) {
                ClearWorkspace(path_output);
            }
        
            EnsureTrailingSlash(path_output);
        
            cy = new ConfigYaml("sensors");
            cy->addKey("app_log");
            cy->addKey("falco_log");
            cy->addKey("suricata_log");
            cy->addKey("redis_host");
            cy->addKey("redis_port");
            cy->ParsConfig();
            
            if (app_log == "indef") app_log = cy->getParameter("app_log");
            if (falco_log == "indef") falco_log = cy->getParameter("falco_log");
            if (suricata_log == "indef") suricata_log = cy->getParameter("suricata_log");
            if (redis_host.empty()) redis_host = cy->getParameter("redis_host");
            
            app_log_status = (app_log != "indef");
            falco_log_status = (falco_log != "indef");
            suricata_log_status = (suricata_log != "indef");
        }
    }
    
    return 1;
}

string CObject::GetProbeTime() {
    time_t rawtime;
    struct tm * timeinfo;
        
    time(&rawtime);
    if (timezone_offset != 0) rawtime = rawtime + timezone_offset*3600;
    
    timeinfo = localtime(&rawtime);
    strftime(collector_time, sizeof(collector_time), "%Y-%m-%d %H:%M:%S",timeinfo);
    
    return string(collector_time);
}

void CObject::SysLog(char* info) {
    //If info equael NULL function send var SysLogInfo as String to SysLog
    if (info == NULL) daemon_log(LOG_ERR, "%s", sys_log_info);
    else daemon_log(LOG_ERR, "%s", info);
}

void CObject::ReplaceAll(string& input, const string& from, const string& to) {
  size_t pos = 0;
  while ((pos = input.find(from, pos)) != string::npos) {
    input.replace(pos, from.size(), to);
    pos += to.size();
  }
}

bool CObject::IsRunningInDockerContainer() {
    // check file /.dockerenv
    std::ifstream dockerenv("/.dockerenv");
    if (dockerenv.good()) {
        return true;
    }

    // check cgroup in /proc/1/cgroup
    std::ifstream cgroup("/proc/1/cgroup");
    if (cgroup.good()) {
        std::string line;
        while (std::getline(cgroup, line)) {
            if (line.find("/docker/") != std::string::npos ||
                line.find("/lxc/") != std::string::npos) {
                return true;
            }
        }
    }

    // check content /proc/self/cgroup
    std::ifstream selfcgroup("/proc/self/cgroup");
    if (selfcgroup.good()) {
        std::string line;
        while (std::getline(selfcgroup, line)) {
            if (line.find("docker") != std::string::npos ||
                line.find("lxc") != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

void Alert::CreateAlertUUID(void) {
    
    std::stringstream ss;
    
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    ss << uuid; 
    alert_uuid = ss.str();
}