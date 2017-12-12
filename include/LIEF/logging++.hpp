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
#endif

#endif
