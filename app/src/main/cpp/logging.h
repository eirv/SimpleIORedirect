#pragma once

#include <android/log.h>

#ifndef LOG_TAG
#define LOG_TAG "IORedirect"
#endif

#ifndef NDEBUG
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#else
#define LOGE(...)
#define LOGD(...)
#define LOGV(...)
#endif
