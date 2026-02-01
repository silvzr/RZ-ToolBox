/**
 * Zygisk Mountinfo Leak Fix Module
 * 
 * Complete implementation compatible with ReZygisk C API v5.
 * Prevents root detection via /proc/self/mountinfo leakage.
 * 
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <mntent.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <android/log.h>

#include "zygisk.h"

// ============================================================================
// Logging
// ============================================================================

#define LOG_TAG "MountinfoFix"
#ifdef NDEBUG
#define LOGD(...) ((void)0)
#define LOGI(...) ((void)0)
#else
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#endif
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================================
// Constants
// ============================================================================

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

#define MAX_MOUNTS 512
#define MAX_PATH 512

// ============================================================================
// Module State
// ============================================================================

typedef struct {
    struct rezygisk_api *api;
    bool is_deny_listed;
    int saved_ns_fd;
    bool is_first_start;
} module_state_t;

static module_state_t g_state = {
    .api = NULL,
    .is_deny_listed = false,
    .saved_ns_fd = -1,
    .is_first_start = false
};

// ============================================================================
// Suspicious Mount Detection
// ============================================================================

static const char *suspicious_patterns[] = {
    "/adb/modules",
    "/data/adb/modules",
    "magisk",
    "KSU",
    "APatch",
    "zygisk",
    NULL
};

static int is_suspicious_mount(const struct mntent *mnt) {
    if (!mnt || !mnt->mnt_dir || !mnt->mnt_fsname) {
        return 0;
    }

    for (int i = 0; suspicious_patterns[i] != NULL; i++) {
        const char *pattern = suspicious_patterns[i];
        
        if (strstr(mnt->mnt_dir, pattern) != NULL) {
            LOGD("Suspicious mount dir: %s (pattern: %s)", mnt->mnt_dir, pattern);
            return 1;
        }
        
        if (strstr(mnt->mnt_fsname, pattern) != NULL) {
            LOGD("Suspicious mount source: %s (pattern: %s)", mnt->mnt_fsname, pattern);
            return 1;
        }
    }

    return 0;
}

// ============================================================================
// Mount Namespace Management
// ============================================================================

static int collect_suspicious_mounts(char mounts[][MAX_PATH], int max_count) {
    FILE *mtab = setmntent("/proc/self/mounts", "r");
    if (!mtab) {
        LOGE("Failed to open /proc/self/mounts: %s", strerror(errno));
        return 0;
    }

    int count = 0;
    struct mntent *mnt;
    while ((mnt = getmntent(mtab)) != NULL && count < max_count) {
        if (is_suspicious_mount(mnt)) {
            strncpy(mounts[count], mnt->mnt_dir, MAX_PATH - 1);
            mounts[count][MAX_PATH - 1] = '\0';
            count++;
        }
    }

    endmntent(mtab);
    LOGD("Found %d suspicious mounts", count);
    return count;
}

static void unmount_suspicious_mounts(char mounts[][MAX_PATH], int count) {
    for (int i = count - 1; i >= 0; i--) {
        if (mounts[i][0] != '\0') {
            LOGD("Unmounting: %s", mounts[i]);
            if (umount2(mounts[i], MNT_DETACH) != 0) {
                LOGD("umount2 failed for %s: %s", mounts[i], strerror(errno));
            }
        }
    }
}

static int create_clean_mount_namespace(void) {
    static char suspicious_mounts[MAX_MOUNTS][MAX_PATH];

    LOGD("Creating clean mount namespace");

    if (g_state.is_first_start) {
        if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) == -1) {
            LOGD("mount MS_SLAVE failed: %s (non-fatal)", strerror(errno));
        }

        if (unshare(CLONE_NEWNS) != 0) {
            LOGE("unshare(CLONE_NEWNS) failed: %s", strerror(errno));
            return -errno;
        }

        int count = collect_suspicious_mounts(suspicious_mounts, MAX_MOUNTS);
        if (count > 0) {
            unmount_suspicious_mounts(suspicious_mounts, count);
            LOGI("Cleaned %d suspicious mounts", count);
        }
    } else {
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
            LOGD("mount MS_PRIVATE failed: %s (non-fatal)", strerror(errno));
        }
    }

    return 0;
}

// ============================================================================
// Module Callbacks (ReZygisk ABI)
// ============================================================================

static void pre_app_specialize(void *self, void *args) {
    (void)self; // Module impl pointer, not used
    
    // Cast to the correct args type
    struct app_specialize_args_v5 *app_args = (struct app_specialize_args_v5 *)args;
    (void)app_args; // Can be used to get package name if needed

    if (!g_state.api) {
        LOGE("API not initialized");
        return;
    }

    // Get process flags from ReZygisk
    uint32_t flags = 0;
    if (g_state.api->get_flags) {
        flags = g_state.api->get_flags();
    }

    g_state.is_deny_listed = (flags & PROCESS_ON_DENYLIST) != 0;
    g_state.is_first_start = (flags & PROCESS_IS_FIRST_STARTED) != 0;

    if (!g_state.is_deny_listed) {
        LOGD("App not on denylist, skipping mount fix");
        return;
    }

    LOGI("App is on denylist, applying mount namespace fix");

    // Create clean mount namespace
    if (create_clean_mount_namespace() != 0) {
        LOGE("Failed to create clean mount namespace");
    }

}

static void post_app_specialize(void *self, const void *args) {
    (void)self;
    (void)args;

    if (g_state.api->set_option) {
        g_state.api->set_option(g_state.api->impl, DLCLOSE_MODULE_LIBRARY);
    }

    g_state.api = NULL;
    g_state.is_first_start = false;
}

static void pre_server_specialize(void *self, void *args) {
    (void)self;
    (void)args;
    // No-op for system_server
}

static void post_server_specialize(void *self, const void *args) {
    (void)self;
    (void)args;
    // No-op for system_server
}

// ============================================================================
// Module ABI Registration
// ============================================================================

static struct rezygisk_abi module_abi = {
    .api_version = REZYGISK_API_VERSION,
    .impl = NULL,
    .pre_app_specialize = pre_app_specialize,
    .post_app_specialize = post_app_specialize,
    .pre_server_specialize = pre_server_specialize,
    .post_server_specialize = post_server_specialize
};

/**
 * Module entry point - called by ReZygisk loader
 * 
 * @param api Pointer to ReZygisk API structure
 * @param env JNI environment (can be used for JNI operations)
 */
__attribute__((visibility("default")))
void zygisk_module_entry(void *api_ptr, void *env) {
    (void)env; // JNIEnv*, not used in this module
    
    struct rezygisk_api *api = (struct rezygisk_api *)api_ptr;
    
    LOGD("Mountinfo leak fix module loading");
    
    // Store the API for later use
    g_state.api = api;
    
    // Register this module with ReZygisk
    if (api->register_module) {
        if (!api->register_module(api, &module_abi)) {
            LOGE("Failed to register module with ReZygisk");
            return;
        }
    }
    
    LOGI("Mountinfo leak fix module registered successfully");
}

// ============================================================================
// Companion Daemon Entry
// ============================================================================

/**
 * Companion entry point - runs with root privileges
 * Called for each connected module instance in the daemon process.
 * 
 * @param client_fd Socket connection to the Zygisk module
 */
__attribute__((visibility("default")))
void zygisk_companion_entry(int client_fd) {
    LOGD("Companion handler called (fd=%d)", client_fd);
    
    // This module doesn't need companion functionality
    // The mount namespace fix is done entirely in the app process
    // Just close the connection
    (void)client_fd;
}
