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

#ifndef MAIN_H
#define	MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <execinfo.h>
#include <wait.h>
#include <wchar.h>
#include <pthread.h> 
#include <semaphore.h> 
#include <signal.h>
#include <yaml.h>
#include <netdb.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <cassert>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <list>
#include <vector>
#include <memory>
#include <regex>


#define BOOST_SPIRIT_THREADSAFE
#include <boost/optional.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/asio.hpp>
#include <boost/regex.hpp>

/* Size limit control */
#define OS_LONG_HEADER_SIZE  256     /* Maximum log header size */
#define OS_DATETIME_SIZE     32      /* DATETIME size */
#define OS_PAYLOAD_SIZE      20480    /* Size for logs, sockets, etc */
#define OS_HEADER_SIZE       128     /* Maximum header size */
#define LOGS_QUEUE_SIZE 200000
#define EOF_COUNTER 100
#define STARTUP_TIMER 30
#define DELIM "."

#define CONFIG_FILE "/etc/altprobe/altprobe.yaml"
#define PID_FILE "/var/run/altprobe.pid"
#define DAEMON_NAME "altprobe"

#endif	/* MAIN_H */