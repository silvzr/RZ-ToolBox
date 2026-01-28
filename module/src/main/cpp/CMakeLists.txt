# CMakeLists.txt for Zygisk Mountinfo Leak Fix Module
# 
# Build with Android NDK CMake toolchain:
#   cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 \
#         -DCMAKE_BUILD_TYPE=Release .
#   make

cmake_minimum_required(VERSION 3.10)
if(NOT DEFINED MODULE_NAME)
    set(MODULE_NAME rz_toolbox)
endif()

project(${MODULE_NAME} C)

# Sources
set(SOURCES
    zygisk_mountinfo_fix.c
)

# Headers
set(HEADERS
    zygisk.h
)

# Build shared library
add_library(${MODULE_NAME} SHARED ${SOURCES} ${HEADERS})

# Use project name for easier reference
set(PROJECT_NAME ${MODULE_NAME})

# Compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
)

# Release-specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(${PROJECT_NAME} PRIVATE NDEBUG)
endif()

# Linker flags
target_link_options(${PROJECT_NAME} PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
)

# Link Android log library
find_library(LOG_LIB log)
target_link_libraries(${PROJECT_NAME} ${LOG_LIB})

# Installation
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib/${ANDROID_ABI}
)
