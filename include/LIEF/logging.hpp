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

namespace LIEF {
static const char* logging_config = R"config(
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

class DLL_PUBLIC Logger {
  public:
  Logger(void);
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  ~Logger(void);

};




}

#endif
