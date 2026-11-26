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

#ifndef SOURCE_H
#define SOURCE_H

#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>

#include "hiredis.h"
#include "sinks.h"
#include "cobject.h"

using namespace std;

// Lifecycle shared by sensor and worker modules. main.cpp calls Open(), runs
// Go() on the module's worker thread, then calls Close() before joining it.
// Shared stop state is atomic; WaitForStop() supports interruptible backoff.
class Source : public CObject {
public:
    std::atomic<bool> source_status{true}; // Stop signal shared with the worker.
    std::mutex stop_mutex;
    std::condition_variable stop_ready;
    void RequestStop() { source_status = false; stop_ready.notify_all(); }
    void WaitForStop(std::chrono::milliseconds duration) {
        std::unique_lock<std::mutex> lock(stop_mutex);
        stop_ready.wait_for(lock, duration, [&] { return !source_status.load(); });
    }
    bool redis_status;       // Redis connection status
    string redis_key;        // Redis key for this source
    string config_key;       // Configuration key name
    string env_key;          // Environment variable key name
    
    redisReply* reply;       // Redis response object
    redisContext* c;         // Redis connection context
    
    string json_report;      // JSON formatted report buffer
    
    // Output interfaces (sinks)
    Sinks sk;
    
    // Default constructor
    Source() {
        source_status = true;
        redis_status = false;
        reply = nullptr;      // Initialize pointer to null
        c = nullptr;          // Initialize pointer to null
    }
    
    // Parameterized constructor
    Source(string ckey, string ekey) {
        source_status = true;
        redis_status = false;
        config_key = ckey;
        env_key = ekey;
        reply = nullptr;      // Initialize pointer to null
        c = nullptr;          // Initialize pointer to null
    }
    
    // Load configuration for this source
    virtual bool GetConfig(int mode);
    
    // Get current source status
    virtual bool GetStatus() { return source_status; }
    
    /* Start monitoring. */
    virtual bool Open() { return source_status; }
    
    /* Stop monitoring. */
    virtual void Close() { RequestStop(); }
    
    /* Monitoring. */
    virtual bool Go() { return true; }
    
    virtual ~Source() {}

protected:
    bool InitializeRedisSession();
    
};

#endif /* SOURCE_H */
