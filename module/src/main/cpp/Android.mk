# Android.mk for Zygisk Mountinfo Leak Fix Module
#
# Build with:
#   ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk
#
# Or use standalone toolchain:
#   aarch64-linux-android-clang -shared -fPIC -O2 -DNDEBUG \
#       -o libmountinfofix.so zygisk_mountinfo_fix.c -llog

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(MODULE_NAME),)
    MODULE_NAME := rz_toolbox
endif()

LOCAL_MODULE := $(MODULE_NAME)
LOCAL_SRC_FILES := zygisk_mountinfo_fix.c
LOCAL_CFLAGS := -Wall -Wextra -O2 -fvisibility=hidden
LOCAL_LDLIBS := -llog
LOCAL_LDFLAGS := -Wl,--gc-sections

# Strip symbols in release for smaller binary
ifeq ($(NDK_DEBUG),0)
    LOCAL_CFLAGS += -DNDEBUG -ffunction-sections -fdata-sections
    LOCAL_LDFLAGS += -Wl,--strip-all
endif

include $(BUILD_SHARED_LIBRARY)
