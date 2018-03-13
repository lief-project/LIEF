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
#ifndef C_LIEF_MACHO_ENUM_TO_STRING_H_
#define C_LIEF_MACHO_ENUM_TO_STRING_H_

#include "LIEF/visibility.h"
#include "LIEF/MachO/enums.h"

#ifdef __cplusplus
extern "C" {
#endif

LIEF_API const char* LOAD_COMMAND_TYPES_to_string(enum LIEF_MACHO_LOAD_COMMAND_TYPES e);
LIEF_API const char* MACHO_TYPES_to_string(enum LIEF_MACHO_MACHO_TYPES e);
LIEF_API const char* FILE_TYPES_to_string(enum LIEF_MACHO_FILE_TYPES e);
LIEF_API const char* CPU_TYPES_to_string(enum LIEF_MACHO_CPU_TYPES e);
LIEF_API const char* HEADER_FLAGS_to_string(enum LIEF_MACHO_HEADER_FLAGS e);
LIEF_API const char* MACHO_SECTION_TYPES_to_string(enum LIEF_MACHO_MACHO_SECTION_TYPES e);
LIEF_API const char* MACHO_SYMBOL_TYPES_to_string(enum LIEF_MACHO_MACHO_SYMBOL_TYPES e);
LIEF_API const char* N_LIST_TYPES_to_string(enum LIEF_MACHO_N_LIST_TYPES e);
LIEF_API const char* SYMBOL_DESCRIPTIONS_to_string(enum LIEF_MACHO_SYMBOL_DESCRIPTIONS e);

#ifdef __cplusplus
}
#endif


#endif
