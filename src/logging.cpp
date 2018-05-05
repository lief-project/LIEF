/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "LIEF/config.h"
#include "LIEF/logging.hpp"
#include "LIEF/logging++.hpp"
#include <map>

#if defined(LIEF_LOGGING_SUPPORT)
INITIALIZE_EASYLOGGINGPP
#endif

static LIEF::Logger logger;

namespace LIEF {

const char* logging_config = R"config(
* GLOBAL:
   FORMAT               = "%msg"
   ENABLED              = true
   TO_STANDARD_OUTPUT   = true
   TO_FILE              = false
   PERFORMANCE_TRACKING = true

* DEBUG:
   FORMAT  = "%func %msg"
   Enabled = true
)config";

const char* logging_config_disabled = R"config(
* GLOBAL:
   FORMAT               = "%msg"
   ENABLED              = false
   TO_STANDARD_OUTPUT   = false
   TO_FILE              = false
   PERFORMANCE_TRACKING = false

* DEBUG:
   FORMAT  = "%func %msg"
   Enabled = false
)config";




Logger::~Logger(void) = default;

const char* to_string(LOGGING_LEVEL e) {
  const std::map<LOGGING_LEVEL, const char*> enumStrings {
    { LOGGING_LEVEL::LOG_GLOBAL,   "GLOBAL"  },
    { LOGGING_LEVEL::LOG_TRACE,    "TRACE"   },
    { LOGGING_LEVEL::LOG_DEBUG,    "DEBUG"   },
    { LOGGING_LEVEL::LOG_FATAL,    "FATAL"   },
    { LOGGING_LEVEL::LOG_ERROR,    "ERROR"   },
    { LOGGING_LEVEL::LOG_WARNING,  "WARNING" },
    { LOGGING_LEVEL::LOG_INFO,     "INFO"    },
    { LOGGING_LEVEL::LOG_VERBOSE,  "VERBOSE" },
    { LOGGING_LEVEL::LOG_UNKNOWN,  "UNKNOWN" },
  };
  auto   it  = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

Logger::Logger(void)
{
#if defined(LIEF_LOGGING_SUPPORT)
  (void)el::Loggers::getLogger("default");
  this->enable();
  this->disable();
#endif
}


void Logger::disable(void) {
#if defined(LIEF_LOGGING_SUPPORT)
  el::Loggers::setLoggingLevel(el::Level::Unknown);
  el::Configurations conf;
  conf.setToDefault();
  conf.parseFromText(logging_config_disabled);
  el::Loggers::reconfigureAllLoggers(conf);
#endif
}

void Logger::enable(void) {
#if defined(LIEF_LOGGING_SUPPORT)
  el::Configurations conf;
  conf.setToDefault();
  conf.parseFromText(logging_config);
  el::Loggers::setDefaultConfigurations(conf, true);

  el::Loggers::addFlag(el::LoggingFlag::HierarchicalLogging);
  el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
  el::Loggers::addFlag(el::LoggingFlag::ImmediateFlush);
  el::Loggers::addFlag(el::LoggingFlag::CreateLoggerAutomatically);
  el::Loggers::setLoggingLevel(el::Level::Fatal);
#endif
}


void Logger::set_verbose_level(uint32_t level) {

#if defined(LIEF_LOGGING_SUPPORT)
  Logger::enable();
  el::Loggers::setVerboseLevel(level);
#endif
}


void Logger::set_level(LOGGING_LEVEL level) {

#if defined(LIEF_LOGGING_SUPPORT)
  Logger::enable();
  el::Loggers::setLoggingLevel(static_cast<el::Level>(level));

  if (level == LOGGING_LEVEL::LOG_DEBUG) {
    set_verbose_level(VDEBUG);
  }
#endif
}

}


