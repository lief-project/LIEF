#pragma once

#if defined(LIEF_LOGGING_SUPPORT)
#include "easylogging++.h"
#else
#include <iostream>
#define VLOG(...) std::cout
#define LOG(...) std::cout
#define LOG_IF(...) std::cout
#endif
