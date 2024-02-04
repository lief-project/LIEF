/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <stdint.h>
#include "LIEF/visibility.h"

#ifndef C_LIEF_LOGGING_H_
#define C_LIEF_LOGGING_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Disable the logging module */
LIEF_API void lief_logging_disable(void);

/** @brief Enable the logging module globally*/
LIEF_API void lief_logging_enable(void);

/** @brief Update logging level */
LIEF_API void lief_logging_set_level(uint32_t level);

#ifdef __cplusplus
}
#endif

#endif

