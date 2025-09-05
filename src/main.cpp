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

#include "collector.h"
#include "applog.h"
#include "falco.h"
#include "suricata.h"
#include "logs.h"
#include "scanners.h"

Collector collector;
pthread_t pthread_collector;

void* exit_thread_collector_arg;
void exit_thread_collector(void* arg) { collector.Close(); }

void * thread_collector(void *arg) {
    
    pthread_cleanup_push(exit_thread_collector, exit_thread_collector_arg);
    
    while (collector.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

AppLog applog("app_redis", "SENSORS_APP_REDIS");
pthread_t pthread_applog;

void* exit_thread_applog_arg;
void exit_thread_applog(void* arg) { applog.Close(); }

void * thread_applog(void *arg) {
    
    pthread_cleanup_push(exit_thread_applog, exit_thread_applog_arg);
    
    while (applog.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Falco falco("falco_redis", "SENSORS_FALCO_REDIS");
pthread_t pthread_falco;

void* exit_thread_falco_arg;
void exit_thread_falco(void* arg) { falco.Close(); }

void * thread_falco(void *arg) {
    
    pthread_cleanup_push(exit_thread_falco, exit_thread_falco_arg);
    
    while (falco.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Suricata suricata("suricata_redis", "SENSORS_SURICATA_REDIS");
pthread_t pthread_suricata;

void* exit_thread_suricata_arg;
void exit_thread_suricata(void* arg) { suricata.Close(); }

void * thread_suricata(void *arg) {
    
    pthread_cleanup_push(exit_thread_suricata, exit_thread_suricata_arg);
    
    while (suricata.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Logs logs;
pthread_t pthread_logs;

void* exit_thread_logs_arg;
void exit_thread_logs(void* arg) { logs.Close(); }

void * thread_logs(void *arg) {
    
    pthread_cleanup_push(exit_thread_logs, exit_thread_logs_arg);
    
    while (logs.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Scanners scanners;
pthread_t pthread_scanners;

void* exit_thread_scanners_arg;
void exit_thread_scanners(void* arg) { scanners.Close(); }

void * thread_scanners(void *arg) {
    
    pthread_cleanup_push(exit_thread_scanners, exit_thread_scanners_arg);
    
    while (scanners.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

int LoadConfig()
{
    //collector
    if (!collector.GetConfig()) return 0;
    
    //applog
    if (!applog.GetConfig()) return 0;
    
    //falco
    if (!falco.GetConfig()) return 0;
    
    //suricata
    if (!suricata.GetConfig()) return 0;
    
    //logs
    if (!logs.GetConfig()) return 0;
    
    // scanners
    if (!scanners.GetConfig()) return 0;
    
    return 1;
}

       
int InitThreads(int mode, pid_t pid)
{
    int arg = 1;
    
    //collector
    if (collector.GetStatus() > 0) {
        
        if (!collector.Open() > 0) {
            daemon_log(LOG_ERR,"Error: cannot open Collector module");
            return 0;
        }
    
        if (pthread_create(&pthread_collector, NULL, thread_collector, &arg)) {
            daemon_log(LOG_ERR,"Error: creating thread for Collector module");
            return 0;
        } 
    }
    
    //applog
    if (applog.GetStatus() > 0) {
        
        if (applog.Open() > 0) {
            
            if (pthread_create(&pthread_applog, NULL, thread_applog, &arg)) {
                daemon_log(LOG_ERR,"Error: creating thread for AppLog module");
                return 0;
            }
        } else daemon_log(LOG_ERR,"Warning: AppLog source is disabled");
    } 
    
    //falco
    if (falco.GetStatus() > 0) {
        
        if (falco.Open() > 0) {
            
            if (pthread_create(&pthread_falco, NULL, thread_falco, &arg)) {
                daemon_log(LOG_ERR,"Error: creating thread for Falco module");
                return 0;
            }
        } else daemon_log(LOG_ERR,"Warning: Falco source is disabled");
    } 
    
    //suricata
    if (suricata.GetStatus() > 0) {
        
        if (suricata.Open() > 0) {
            
            if (pthread_create(&pthread_suricata, NULL, thread_suricata, &arg)) {
                daemon_log(LOG_ERR,"Error: creating thread for Suricata module");
                return 0;
            }
            
        } else daemon_log(LOG_ERR,"Warning: Suricata source is disabled");
    }
    
    //logs
    if (logs.GetStatus() > 0) {
        
        if (logs.Open() > 0) {
            
            if (pthread_create(&pthread_logs, NULL, thread_logs, &arg)) {
                daemon_log(LOG_ERR,"Error: creating thread for Log module");
                return 0;
            }
            
        } else daemon_log(LOG_ERR,"Warning: Log source is disabled");
    }
    
    // scanners
    if (scanners.GetStatus() > 0) {
        
        if (!scanners.Open(mode,pid)) {
            daemon_log(LOG_ERR,"Error: cannot open Scanners module");
            return 0;
        }
        
        if (pthread_create(&pthread_scanners, NULL, thread_scanners, &arg)) {
            daemon_log(LOG_ERR,"Error: creating thread for Scanners module");
            return 0;
        } 
    }
    
    return 1;
}

void KillThreads(void)
{
    //collector
    if (collector.GetStatus()) {
        pthread_cancel(pthread_collector);
        pthread_join(pthread_collector, NULL); 
    }
    
    //applog
    if (applog.GetStatus()) {
        pthread_cancel(pthread_applog);
        pthread_join(pthread_applog, NULL);
    }
    
    //falco
    if (falco.GetStatus()) {
        pthread_cancel(pthread_falco);
        pthread_join(pthread_falco, NULL);
    }
    
    //suricata
    if (suricata.GetStatus()) {
        pthread_cancel(pthread_suricata);
        pthread_join(pthread_suricata, NULL);
    }
    
    //logs
    if (logs.GetStatus()) {
        pthread_cancel(pthread_logs);
        pthread_join(pthread_logs, NULL);
    }
    
    // scanners
    if (scanners.GetStatus()) {
        pthread_cancel(pthread_scanners);
        pthread_join(pthread_scanners, NULL); 
    }
}

void cleanup() {
    
    daemon_log(LOG_INFO, "Info: exiting...");
    daemon_retval_send(255);
    daemon_signal_done();
    daemon_pid_file_remove();
}

int start(pid_t pid) {
    
    int ret;
    
    if (!LoadConfig()) return 1;
    
    int startup_timer = STARTUP_TIMER;
        
    /* Prepare for return value passing from the initialization procedure of the daemon process */
    if (daemon_retval_init() < 0) {
        
        daemon_log(LOG_ERR, "Error: failed to create pipe");
        
        return 1;
    }

    /* Do the fork */
    if ((pid = daemon_fork()) < 0) {

        /* Exit on error */
        daemon_retval_done();
        
        return 1;

    } else if (pid) { /* The parent */
        
        /* Wait for timeout in seconds for the return value passed from the daemon process */
        if ((ret = daemon_retval_wait(startup_timer)) < 0) {
            
            daemon_log(LOG_ERR, "Error: could not receive return value from Altprobe process: %s", strerror(errno));
            
            return 255;
        }

        daemon_log(ret != 0 ? LOG_ERR : LOG_INFO, "Info: Altprobe service started with code %i", ret);
        
        return ret;

    } else { /* The daemon */
        
        int fd, quit = 0;
        fd_set fds;

        /* Close FDs */
        if (daemon_close_all(-1) < 0) {
            daemon_log(LOG_ERR, "Error: failed to close all file descriptors: %s", strerror(errno));

            /* Send the error condition to the parent process */
            daemon_retval_send(1);
            
            cleanup();
            return 1;
        }

        /* Create the PID file */
        if (daemon_pid_file_create() < 0) {
            daemon_log(LOG_ERR, "Error: could not create PID file (%s)", strerror(errno));
            daemon_retval_send(2);
            
            cleanup();
            return 1;
        }

        /* Initialize signal handling */
        if (daemon_signal_init(SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, 0) < 0) {
            daemon_log(LOG_ERR, "Error: could not register signal handlers (%s)", strerror(errno));
            daemon_retval_send(3);
            
            cleanup();
            return 1;
        }

        /*... do some further init work here */
        if (!InitThreads(1,pid)) {
            
            daemon_retval_send(4);
            
            KillThreads();
            cleanup();
            return 1;
        }

        /* Send OK to parent process */
        daemon_retval_send(0);

        daemon_log(LOG_INFO, "Info: Altprobe service started");

        /* Prepare for select() on the signal fd */
        FD_ZERO(&fds);
        fd = daemon_signal_fd();
        FD_SET(fd, &fds);
        
        while (!quit) {
            fd_set fds2 = fds;

            /* Wait for an incoming signal */
            if (select(FD_SETSIZE, &fds2, 0, 0, 0) < 0) {

                /* If we've been interrupted by an incoming signal, continue */
                if (errno == EINTR)
                    continue;

                daemon_log(LOG_ERR, "Error: select(): %s", strerror(errno));
                break;
            }

            /* Check if a signal has been recieved */
            if (FD_ISSET(fd, &fds2)) {
                
                int sig;

                /* Get signal */
                if ((sig = daemon_signal_next()) <= 0) {
                    daemon_log(LOG_ERR, "Error: daemon_signal_next() failed: %s", strerror(errno));
                    break;
                }

                /* Dispatch signal */
                switch (sig) {
                    case SIGHUP:
                    case SIGINT:
                    case SIGQUIT:
                    case SIGTERM:
                        daemon_log(LOG_WARNING, "Info: got SIGHUP, SIGINT, SIGQUIT or SIGTERM");
                        quit = 1;
                        break;
                }
            }
        }
        
        KillThreads();
        cleanup();
    }
    
    return 0;
}

static void sigHandler (int signo) {
    printf ("Info: got SIGHUP, SIGINT, SIGQUIT or SIGTERM\n");
    KillThreads();
    
    exit (EXIT_SUCCESS);
}

int startTest() {
    
    if (!LoadConfig()) return 1;
    
    pid_t pid = getpid();
    
    if (!InitThreads(2,pid)) {
            
        KillThreads();
        return 1;
    }
    
    if (signal (SIGINT, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Error: cannot handle SIGINT!\n");
        KillThreads();
        exit (EXIT_FAILURE);
    }
    
    if (signal (SIGHUP, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Error: cannot handle SIGHUP!\n");
        KillThreads();
        exit (EXIT_FAILURE);
    }
    
    if (signal (SIGQUIT, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Error: cannot handle SIGQUIT!\n");
        KillThreads();
        exit (EXIT_FAILURE);
    }
    
    if (signal (SIGTERM, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Error: cannot handle SIGTERM!\n");
        KillThreads();
        exit (EXIT_FAILURE);
    }
    
    for (;;) {
        pause ();
        return 0;
    }
}


int main(int argc, char *argv[]) {
    
    pid_t pid;
    int ret;
    
    /* Reset signal handlers */
    if (daemon_reset_sigs(-1) < 0) {
        daemon_log(LOG_ERR, "Error: failed to reset all signal handlers: %s", strerror(errno));
        return 1;
    }

    /* Unblock signals */
    if (daemon_unblock_sigs(-1) < 0) {
        daemon_log(LOG_ERR, "Error: failed to unblock all signals: %s", strerror(errno));
        return 1;
    }

    /* Set indetification string for the daemon for both syslog and PID file */
    daemon_pid_file_ident = daemon_log_ident = daemon_ident_from_argv0(argv[0]);
    
    /* Check if we are called with parameters */
    if (argc == 2) {
        
        if (!strcmp(argv[1], "start")) {
            
            if ((pid = daemon_pid_file_is_running()) >= 0)
                printf( "Warning: Altprobe service is already running (PID: %u)\n", pid);
            else return start(pid);
            
            return 0;
        }
        
        if (!strcmp(argv[1], "test")) {
            
            if ((pid = daemon_pid_file_is_running()) >= 0)
                printf( "Warning: Altprobe service is already running (PID: %u)\n", pid);
            else return startTest();
            
            return 0;
        }
        
        if (!strcmp(argv[1], "stop")) {
             /* Kill daemon with SIGTERM */
             /* Check if the new function daemon_pid_file_kill_wait() is available, if it is, use it. */
             if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
                  printf( "Error: Could not kill Altprobe service process (reason: %s)\n", strerror(errno));
             else printf( "Info: Stopping Altprobe service...\n");
             return ret < 0 ? 1 : 0;
        }
        
        if (!strcmp(argv[1], "status")) {                        
             /* Check that the daemon is not rung twice a the same time */
             if ((pid = daemon_pid_file_is_running()) >= 0)
                  printf( "Info: Altprobe service is running (PID: %u)\n", pid);
             else printf( "Info: Altprobe service isn't running \n");
             return 0;
        }
    }
    
    printf( "Usage: altprobe {start|status|stop|test}\n");
    
    return 0;
}





