/**
 * ReZygisk API Header
 * Compatible with ReZygisk C API version 5
 * Source: https://github.com/PerformanC/ReZygisk
 */

#ifndef REZYGISK_API_H
#define REZYGISK_API_H

#include <jni.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define REZYGISK_API_VERSION 5

// Process flags returned by get_flags()
enum rezygisk_flags {
    PROCESS_GRANTED_ROOT = (1u << 0),
    PROCESS_ON_DENYLIST = (1u << 1),

    PROCESS_IS_MANAGER = (1u << 27),
    PROCESS_ROOT_IS_APATCH = (1u << 28),
    PROCESS_ROOT_IS_KSU = (1u << 29),
    PROCESS_ROOT_IS_MAGISK = (1u << 30),
    PROCESS_IS_FIRST_STARTED = (1u << 31),

    PRIVATE_MASK = PROCESS_IS_FIRST_STARTED
};

// App specialization arguments (v5 - latest)
struct app_specialize_args_v5 {
    jint *uid;
    jint *gid;
    jintArray *gids;
    jint *runtime_flags;
    jobjectArray *rlimits;
    jint *mount_external;
    jstring *se_info;
    jstring *nice_name;
    jstring *instruction_set;
    jstring *app_data_dir;

    jintArray *fds_to_ignore;
    jboolean *is_child_zygote;
    jboolean *is_top_app;
    jobjectArray *pkg_data_info_list;
    jobjectArray *whitelisted_data_info_list;
    jboolean *mount_data_dirs;
    jboolean *mount_storage_dirs;

    jboolean *mount_sysprop_overrides;
};

// Server specialization arguments
struct server_specialize_args_v1 {
    jint *uid;
    jint *gid;
    jintArray *gids;
    jint *runtime_flags;
    jlong *permitted_capabilities;
    jlong *effective_capabilities;
};

// Module options
enum rezygisk_options {
    /**
     * Force ReZygisk to umount the root related mounts on this process.
     * This option will only take effect if set in pre...Specialize.
     */
    FORCE_DENYLIST_UNMOUNT = 0,

    /**
     * Once set, ReZygisk will dlclose your library from the process.
     * This happens after post...Specialize.
     * Don't use if you leave references like hooks in the process.
     */
    DLCLOSE_MODULE_LIBRARY = 1
};

// Forward declaration
struct rezygisk_api;

// Module ABI structure - callbacks for the module
struct rezygisk_abi {
    long api_version;
    void *impl;

    void (*pre_app_specialize)(void *self, void *args);
    void (*post_app_specialize)(void *self, const void *args);
    void (*pre_server_specialize)(void *self, void *args);
    void (*post_server_specialize)(void *self, const void *args);
};

// ReZygisk API structure - functions provided by ReZygisk
struct rezygisk_api {
    void *impl;
    
    // Register this module with ReZygisk
    bool (*register_module)(struct rezygisk_api *self, const struct rezygisk_abi *abi);

    // Hook JNI native methods
    void (*hook_jni_native_methods)(JNIEnv *env, const char *class_name, 
                                    JNINativeMethod *methods, int num_methods);
    
    // PLT hook registration (v4+ API)
    void (*plt_hook_register)(dev_t dev, ino_t inode, const char *symbol, 
                              void *new_func, void **old_func);
    
    // Exempt a file descriptor from closing
    void (*exempt_fd)(int fd);

    // Commit PLT hooks
    bool (*plt_hook_commit)(void);
    
    // Connect to companion daemon
    int (*connect_companion)(void *impl);
    
    // Set module options
    void (*set_option)(void *impl, enum rezygisk_options opt);
    
    // Get module directory FD
    int (*get_module_dir)(void *impl);
    
    // Get process flags
    uint32_t (*get_flags)(void);
};

#endif // REZYGISK_API_H
