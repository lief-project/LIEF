#ifndef LIEF_LOGGINGPP_H_
#define LIEF_LOGGINGPP_H_
#include "LIEF/config.h"
#if defined(LIEF_LOGGING_SUPPORT)
#include "easylogging++.h"
#else
#include <iostream>
#define NULL_STREAM if(1){} else std::cerr
#define VLOG(...) NULL_STREAM
#define VLOG_IF(...) NULL_STREAM
#define CVLOG(...) NULL_STREAM
#define LOG(...) NULL_STREAM
#define LOG_IF(...) NULL_STREAM
#define CHECK(...) NULL_STREAM
#define CHECK_EQ(...) NULL_STREAM
#define CHECK_NE(...) NULL_STREAM
#define CHECK_LT(...) NULL_STREAM
#define CHECK_GT(...) NULL_STREAM
#define CHECK_LE(...) NULL_STREAM
#define CHECK_GE(...) NULL_STREAM
#define CHECK_NOTNULL(...) NULL_STREAM
#define CHECK_STREQ(...) NULL_STREAM
#define CHECK_STRNE(...) NULL_STREAM
#define CHECK_STRCASEEQ(...) NULL_STREAM
#define CHECK_STRCASENE(...) NULL_STREAM
#define CHECK_BOUNDS(...) NULL_STREAM
#endif

#endif
