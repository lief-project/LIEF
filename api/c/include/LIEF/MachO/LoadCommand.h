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
#ifndef C_LIEF_MACHO_LOAD_COMMAND_H_
#define C_LIEF_MACHO_LOAD_COMMAND_H_
#include <inttypes.h>

#include "LIEF/MachO/enums.h"
#ifdef __cplusplus
extern "C" {
#endif

struct Macho_Command_t {
  enum LIEF_MACHO_LOAD_COMMAND_TYPES command;
  uint32_t                size;
  uint8_t*                data;
  uint32_t                offset;
};

typedef struct Macho_Command_t Macho_Command_t;


#ifdef __cplusplus
}
#endif

#endif
