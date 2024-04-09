cmake_minimum_required(VERSION 3.22.1)

if (ANDROID_ABI STREQUAL "riscv64")
    set(ANDROID_PLATFORM "android-35")
endif ()

project("io-redirect")

add_library(${PROJECT_NAME} SHARED main.cpp)
target_link_libraries(${PROJECT_NAME} log)
