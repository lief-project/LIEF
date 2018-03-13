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
#ifndef LIEF_LOGGING_H_
#define LIEF_LOGGING_H_

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

namespace LIEF {

//! @brief **Hierarchical** logging level
//!
//! From a given level set, all levels below this
//! level are enabled
//!
//! For example, if LOG_FATAL is enabled then LOG_ERROR, LOG_WARNING are also enabled
enum LOGGING_LEVEL {
  LOG_GLOBAL  = 1,
  LOG_TRACE   = 2,
  LOG_DEBUG   = 4,
  LOG_FATAL   = 8,
  LOG_ERROR   = 16,
  LOG_WARNING = 32,
  LOG_INFO    = 64,
  LOG_VERBOSE = 128,
  LOG_UNKNOWN = 1010,
};

LIEF_API const char* to_string(LOGGING_LEVEL e);

class LIEF_API Logger {
  public:
  Logger(void);
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  //! @brief Disable the logging module
  static void disable(void);

  //! @brief Enable the logging module
  static void enable(void);

  //! @brief Change the logging level (**hierarchical**)
  static void set_level(LOGGING_LEVEL level);

  //! @brief Change the verbose level
  static void set_verbose_level(uint32_t level);

  ~Logger(void);

};




}

#endif
