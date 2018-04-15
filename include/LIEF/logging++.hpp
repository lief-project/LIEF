#ifndef LIEF_LOGGINGPP_H_
#define LIEF_LOGGINGPP_H_
#include "LIEF/config.h"
#if defined(LIEF_LOGGING_SUPPORT)
#include "easylogging++.h"
#else
#include <iostream>
#define NULL_STREAM if(1){} else std::cerr
#define VLOG(...) NULL_STREAM
#define LOG(...) NULL_STREAM
#define LOG_IF(...) NULL_STREAM

#define CHECK(...)
#define CHECK_EQ(...)
#define CHECK_NE(...)
#define CHECK_LT(...)
#define CHECK_LE(...)
#define CHECK_GE(...)
#define CHECK_GT(...)

#define DCHECK(...)
#define DCHECK_EQ(...)
#define DCHECK_NE(...)
#define DCHECK_LT(...)
#define DCHECK_LE(...)
#define DCHECK_GE(...)
#define DCHECK_GT(...)
#endif

#endif
