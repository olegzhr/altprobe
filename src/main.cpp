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

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>

#include "proxy.h"
#include "suricata.h"
#include "modsec.h"
#include "correlator.h"
#include "incident.h"
#include "filter.h"
#include "logs.h"
#include "classify.h"
#include "scanner.h"
#include "trace.h"
#include "llm_guard.h"
#include "trace_delivery.h"
#include "otlp_receiver.h"
#include "openshell.h"

/* ================================================================
 * Global module instances
 * ================================================================ */

Proxy     proxy("proxy_redis", "SOURCES_PROXY_REDIS");
Modsec    modsec;
Suricata suricata;
Openshell openshell;
Correlator correlator;
Incident incident;
Filter filter;
Logs logs;
Scanner scanner;
OtlpReceiver otlp_receiver;
// `trace` itself is defined in trace.cpp (extern in trace.h).

/* ================================================================
 * Thread handles + creation flags (pthread_t is opaque!)
 * ================================================================ */

static pthread_t th_suricata, th_openshell, th_proxy, th_modsec, th_correlator, th_incident, th_filter, th_logs, th_scanner, th_trace;

static int f_suricata = 0, f_openshell = 0, f_proxy = 0, f_modsec = 0, f_correlator = 0, f_incident = 0, f_filter = 0, f_logs = 0, f_scanner = 0, f_trace = 0;

/* ================================================================
 * Generic worker thread template
 * ================================================================ */

#define DEFINE_THREAD(name, module)                              \
static void* thread_##name(void* arg) {                          \
    (void)arg;                                                   \
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);         \
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);        \
    while (module.Go()) {                                        \
        pthread_testcancel();                                    \
    }                                                            \
    return NULL;                                                 \
}

DEFINE_THREAD(suricata, suricata)
DEFINE_THREAD(openshell, openshell)
DEFINE_THREAD(proxy,      proxy)
DEFINE_THREAD(modsec,     modsec)
DEFINE_THREAD(correlator,  correlator)
DEFINE_THREAD(incident,     incident)
DEFINE_THREAD(filter,       filter)
DEFINE_THREAD(logs, logs)
DEFINE_THREAD(scanner, scanner)
DEFINE_THREAD(trace, trace)
static pthread_t th_llm_guard;
static int f_llm_guard = 0;
DEFINE_THREAD(llm_guard, llmGuard)
static pthread_t th_trace_delivery, th_otlp_receiver;
static int f_trace_delivery = 0, f_otlp_receiver = 0;
DEFINE_THREAD(trace_delivery, traceDelivery)
DEFINE_THREAD(otlp_receiver, otlp_receiver)

/* ================================================================
 * Load configuration for all modules
 * ================================================================ */

static bool DeliveryFailed() {
    return otlp_receiver.HasFailed() || traceDelivery.HasFailed();
}

static bool LoadConfig(int run_mode) {
    
    if (!proxy.GetConfig(run_mode)) return false;
    if (!suricata.GetConfig(run_mode)) return false;
    if (!openshell.GetConfig(run_mode)) return false;

    if (!modsec.GetConfig(run_mode)) return false;


    if (!correlator.GetConfig(run_mode)) return false;
    if (!incident.GetConfig(run_mode)) return false;
    
    if (!filter.GetConfig(run_mode)) return false;
    
    if (!logs.GetConfig(run_mode)) return false;
    
    if (!scanner.GetConfig(run_mode)) return false;

    if (!trace.GetConfig(run_mode)) return false;


    loadApiGuardPatterns(CObject::api_guard_path);
    if (!llmGuard.GetConfig(run_mode)) return false;
    
    return true;
}

/* ================================================================
 * Initialize modules and spawn threads
 * ================================================================ */

static bool InitThreads() {
    if (CObject::af_enable || CObject::os_enable || CObject::splunk_enable ||
            CObject::graylog_enable || traceConfig().mode == "external") {
        if (!traceDelivery.Open()) return false;
        if (pthread_create(&th_trace_delivery, NULL, thread_trace_delivery, NULL)) return false;
        f_trace_delivery = 1;
    }
    if (traceConfig().mode == "external") {
        if (!otlp_receiver.Open()) return false;
        if (pthread_create(&th_otlp_receiver, NULL, thread_otlp_receiver, NULL)) return false;
        f_otlp_receiver = 1;
    }
    if (CObject::llm_guard_enabled) {
        if (!llmGuard.Open()) return false;
        if (pthread_create(&th_llm_guard, NULL, thread_llm_guard, NULL)) { llmGuard.Close(); return false; }
        f_llm_guard = 1;
    }
    if (suricata.GetStatus()) {
        if (!suricata.Open() || pthread_create(&th_suricata, NULL, thread_suricata, NULL)) return false;
        f_suricata = 1;
    }
    if (openshell.GetStatus()) {
        if (!openshell.Open() || pthread_create(&th_openshell, NULL, thread_openshell, NULL)) return false;
        f_openshell = 1;
    }
    if (proxy.GetStatus()) {
        if (!proxy.Open() || pthread_create(&th_proxy, NULL, thread_proxy, NULL)) return false;
        f_proxy = 1;
    }

    if (modsec.GetStatus() && modsec.Open())
        if (!pthread_create(&th_modsec, NULL, thread_modsec, NULL))
            f_modsec = 1;


    // Incident delivery runs independently of gateway authorization.
    if (incident.GetStatus() && incident.Open()) {
        if (!pthread_create(&th_incident, NULL, thread_incident, NULL)) f_incident = 1;
        else incident.Close();
    }
    if (correlator.GetStatus() && correlator.Open())
        if (!pthread_create(&th_correlator, NULL, thread_correlator, NULL)) f_correlator = 1;

    if (filter.GetStatus() && filter.Open())
        if (!pthread_create(&th_filter, NULL, thread_filter, NULL))
            f_filter = 1;
    
    if (logs.GetStatus() && logs.Open())
        if (!pthread_create(&th_logs, NULL, thread_logs, NULL))
            f_logs = 1;
    
    if (scanner.GetStatus() && scanner.Open())
        if (!pthread_create(&th_scanner, NULL, thread_scanner, NULL))
            f_scanner = 1;

    if (trace.GetStatus() && trace.Open())
        if (!pthread_create(&th_trace, NULL, thread_trace, NULL))
            f_trace = 1;



    return true;
}

/* ================================================================
 * Safe thread stop helper
 * ================================================================ */

static void stop_thread(pthread_t th, int started, const char* name) {
    if (!started) return;
    pthread_join(th, NULL);
    daemon_log(LOG_INFO, "Thread %s stopped", name);
}

/* ================================================================
 * Graceful shutdown (idempotent)
 * ================================================================ */

static void KillThreads(void) {
    // Cancel shared bounded HTTP clients before waiting for any worker.
    CObject::stopping = true;
    otlp_receiver.Close();
    llmGuard.Close();
    suricata.Close();
    openshell.Close();
    proxy.Close();
    modsec.Close();
    correlator.Close();
    incident.Close();
    filter.Close();
    logs.Close();
    scanner.Close();
    trace.Close();

    stop_thread(th_llm_guard, f_llm_guard, "llm-guard");
    stop_thread(th_logs,        f_logs,          "logs");
    stop_thread(th_filter,      f_filter,        "filter");
    stop_thread(th_scanner,     f_scanner,       "scanner");
    stop_thread(th_trace,       f_trace,         "trace");
    stop_thread(th_otlp_receiver, f_otlp_receiver, "otlp-receiver");
    traceDelivery.Close();
    stop_thread(th_trace_delivery, f_trace_delivery, "trace-delivery");
    stop_thread(th_incident,    f_incident,      "incident");
    stop_thread(th_correlator,  f_correlator,    "correlator");
    stop_thread(th_modsec,       f_modsec,       "modsec");
    stop_thread(th_suricata, f_suricata, "suricata");
    stop_thread(th_openshell, f_openshell, "openshell");
    stop_thread(th_proxy,       f_proxy,        "proxy");
}

/* ================================================================
 * Daemon cleanup
 * ================================================================ */

static void cleanup(void) {
    daemon_signal_done();
    daemon_pid_file_remove();
}

/* ================================================================
 * Daemon start
 * ================================================================ */

int start(pid_t pid) {
    int ret;
    
    if (!LoadConfig(0)) return 1;
    
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
        if (!InitThreads()) {
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
        
        if (fd < 0) {
            daemon_log(LOG_ERR, "Error: daemon_signal_fd() failed");
            KillThreads();
            cleanup();
            return 1;
        }
        
        FD_SET(fd, &fds);
        
        while (!quit && !DeliveryFailed()) {
            fd_set fds2 = fds;

            /* Wait for an incoming signal */
            //if (select(FD_SETSIZE, &fds2, 0, 0, 0) < 0) {
            struct timeval delivery_tick = {1, 0};
            if (select(fd + 1, &fds2, NULL, NULL, &delivery_tick) < 0) {
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
        
        bool delivery_failed = DeliveryFailed();
        KillThreads();
        cleanup();
        if (delivery_failed) return 1;
    }
    
    return 0;
}

static volatile sig_atomic_t signal_received = 0;

static void sigHandler (int signo) {
    printf("\nInfo: Received signal %d\n", signo);
    signal_received = 1;
}

int run(int run_mode) {
    
    if (run_mode == 2) {
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
    }
    
    if (!LoadConfig(run_mode)) {
        fprintf(stderr, "Error: Failed to load configuration\n");
        return 1;
    }
    
    pid_t pid = getpid();
    
    if (!InitThreads()) {
        fprintf(stderr, "Error: Failed to initialize threads\n");
        KillThreads();
        return 1;
    }
    
    if (run_mode == 1) {
        printf("Info: Altprobe in foreground mode started (PID: %d)\n", pid);
        printf("Info: Press Ctrl+C to stop\n");
    } else {
        printf("Info: Altprobe in docker mode started (PID: %d)\n", pid);
    }
    
    struct sigaction sa;
    sa.sa_handler = sigHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "Error: Cannot set SIGINT handler: %s\n", strerror(errno));
        KillThreads();
        return 1;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        fprintf(stderr, "Error: Cannot set SIGTERM handler: %s\n", strerror(errno));
        KillThreads();
        return 1;
    }
    
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        fprintf(stderr, "Error: Cannot set SIGQUIT handler: %s\n", strerror(errno));
        KillThreads();
        return 1;
    }
    
    // Ignore SIGHUP
    signal(SIGHUP, SIG_IGN);
    
    // Wait for signal using select (more reliable than nanosleep)
    while (!signal_received && !DeliveryFailed()) {
        struct timeval tv;
        tv.tv_sec = 1;  // Check every second
        tv.tv_usec = 0;
        
        int ret = select(0, NULL, NULL, NULL, &tv);
        
        if (ret == -1 && errno == EINTR) {
            // Interrupted by signal
            if (signal_received) break;
        }
    }
    
    bool delivery_failed = DeliveryFailed();
    printf("Info: Stopping all threads...\n");
    KillThreads();
    
    printf("Info: Altprobe foreground mode stopped\n");
    return delivery_failed ? 1 : 0;
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
        
        if (!strcmp(argv[1], "run")) {
            if ((pid = daemon_pid_file_is_running()) >= 0)
                printf( "Warning: Altprobe service is already running (PID: %u)\n", pid);
            else return run(1);
            return 0;
        }
        
        if (!strcmp(argv[1], "docker")) {
            if ((pid = daemon_pid_file_is_running()) >= 0)
                printf( "Warning: Altprobe service is already running (PID: %u)\n", pid);
            else return run(2);
            return 0;
        }
        
        if (!strcmp(argv[1], "stop")) {
            if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
                printf( "Error: Could not kill Altprobe service process (reason: %s)\n", strerror(errno));
            else printf( "Info: Stopping Altprobe service...\n");
            return ret < 0 ? 1 : 0;
        }
        
        if (!strcmp(argv[1], "status")) {                        
            if ((pid = daemon_pid_file_is_running()) >= 0)
                printf( "Info: Altprobe service is running (PID: %u)\n", pid);
            else printf( "Info: Altprobe service isn't running \n");
            return 0;
        }
    }
    
    printf( "Usage: altprobe {start|run|docker|status|stop}\n");
    return 0;
}
