/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
namespace logging {

//! @brief **Hierarchical** logging level
//!
//! From a given level set, all levels below this
//! level are enabled
//!
//! For example, if LOG_FATAL is enabled then LOG_ERROR, LOG_WARNING are also enabled
enum LOGGING_LEVEL {
  LOG_TRACE,
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERR,
  LOG_CRITICAL,
};

LIEF_API const char* to_string(LOGGING_LEVEL e);

//! @brief Disable the logging module
LIEF_API void disable(void);

//! @brief Enable the logging module
LIEF_API void enable(void);

//! @brief Change the logging level (**hierarchical**)
LIEF_API void set_level(LOGGING_LEVEL level);

}
}

#endif
