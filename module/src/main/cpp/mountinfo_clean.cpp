/* Copyright 2026 silvzr
 *
 * MountInfo Clean - A Zygisk module that prevents root detection via mount info leakage.
 * Works with ReZygisk by communicating with its daemon to switch mount namespaces.
 *
 * This module switches to a clean mount namespace for denylist apps so that
 * /proc/self/mountinfo doesn't contain suspicious mount entries.
 */

#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <android/log.h>

#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOG_TAG "MountInfoClean"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ReZygisk daemon communication
#ifdef __LP64__
    #define SOCKET_NAME "cp64.sock"
#else
    #define SOCKET_NAME "cp32.sock"
#endif

#define REZYGISK_PATH "/data/adb/rezygisk"

enum DaemonAction : uint8_t {
    ZygoteInjected = 0,
    GetProcessFlags = 1,
    GetInfo = 2,
    ReadModules = 3,
    RequestCompanionSocket = 4,
    GetModuleDir = 5,
    ZygoteRestart = 6,
    SystemServerStarted = 7,
    UpdateMountNamespace = 8
};

enum MountNamespaceState : uint8_t {
    Clean = 0,
    Mounted = 1
};

// Simple I/O helpers
static ssize_t write_uint8(int fd, uint8_t val) {
    return write(fd, &val, sizeof(val));
}

static ssize_t write_uint32(int fd, uint32_t val) {
    return write(fd, &val, sizeof(val));
}

static ssize_t read_uint32(int fd, uint32_t *val) {
    return read(fd, val, sizeof(*val));
}

// Connect to ReZygisk daemon
static int rezygiskd_connect() {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
        LOGE("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
        .sun_path = {0}
    };

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", REZYGISK_PATH, SOCKET_NAME);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOGE("Failed to connect to daemon at %s: %s", addr.sun_path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

// Request mount namespace switch from daemon
static bool switch_to_clean_namespace() {
    int fd = rezygiskd_connect();
    if (fd == -1) {
        return false;
    }

    // Send request for Clean namespace
    write_uint8(fd, UpdateMountNamespace);
    write_uint32(fd, (uint32_t)getpid());
    write_uint8(fd, (uint8_t)Clean);

    // Read response
    uint32_t daemon_pid = 0;
    uint32_t ns_fd = 0;

    if (read_uint32(fd, &daemon_pid) <= 0) {
        LOGE("Failed to read daemon pid");
        close(fd);
        return false;
    }

    if (read_uint32(fd, &ns_fd) <= 0) {
        LOGE("Failed to read namespace fd");
        close(fd);
        return false;
    }

    close(fd);

    if (ns_fd == 0) {
        LOGE("Daemon returned invalid namespace fd (ns_fd=0, daemon_pid=%u)", daemon_pid);
        return false;
    }

    // Construct path to namespace fd in daemon's /proc
    char ns_path[PATH_MAX];
    snprintf(ns_path, sizeof(ns_path), "/proc/%u/fd/%u", daemon_pid, ns_fd);

    // Open and switch to the namespace
    int nsfd = open(ns_path, O_RDONLY);
    if (nsfd == -1) {
        LOGE("Failed to open namespace fd %s: %s", ns_path, strerror(errno));
        return false;
    }

    if (setns(nsfd, CLONE_NEWNS) == -1) {
        LOGE("Failed to setns: %s", strerror(errno));
        close(nsfd);
        return false;
    }

    close(nsfd);
    LOGI("Successfully switched to clean mount namespace");
    return true;
}

class MountInfoClean : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        LOGD("preAppSpecialize: %s", process);

        // Get process flags to check if we should apply clean namespace
        uint32_t flags = api->getFlags();
        bool on_denylist = (flags & zygisk::PROCESS_ON_DENYLIST) != 0;

        if (on_denylist) {
            LOGD("Process %s is on denylist, switching to clean namespace", process);
            
            // Switch to clean namespace BEFORE app runs
            // This ensures /proc/self/mountinfo won't show root-related mounts
            if (switch_to_clean_namespace()) {
                LOGI("Clean namespace active for %s", process);
                
                // Debug: dump mountinfo to see what's actually visible
                FILE* f = fopen("/proc/self/mountinfo", "r");
                if (f) {
                    char line[512];
                    LOGD("=== /proc/self/mountinfo after clean switch ===");
                    while (fgets(line, sizeof(line), f)) {
                        // Remove newline
                        size_t len = strlen(line);
                        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
                        
                        // Log lines containing suspicious keywords
                        if (strstr(line, "magisk") || strstr(line, "KSU") || 
                            strstr(line, "APatch") || strstr(line, "/data/adb")) {
                            LOGD("DETECTED: %s", line);
                        }
                    }
                    LOGD("=== End mountinfo ===");
                    fclose(f);
                }
            } else {
                LOGE("Failed to switch to clean namespace for %s", process);
            }
            // Our job is done, unload the module
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
        // If not on denylist, keep module loaded (or do nothing)

        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        // Don't modify system_server
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(MountInfoClean)
