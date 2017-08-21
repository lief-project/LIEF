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

DLL_PUBLIC const char* LOAD_COMMAND_TYPES_to_string(enum LOAD_COMMAND_TYPES e);
DLL_PUBLIC const char* MACHO_TYPES_to_string(enum MACHO_TYPES e);
DLL_PUBLIC const char* FILE_TYPES_to_string(enum FILE_TYPES e);
DLL_PUBLIC const char* CPU_TYPES_to_string(enum CPU_TYPES e);
DLL_PUBLIC const char* HEADER_FLAGS_to_string(enum HEADER_FLAGS e);
DLL_PUBLIC const char* MACHO_SECTION_TYPES_to_string(enum MACHO_SECTION_TYPES e);
DLL_PUBLIC const char* MACHO_SYMBOL_TYPES_to_string(enum MACHO_SYMBOL_TYPES e);
DLL_PUBLIC const char* N_LIST_TYPES_to_string(enum N_LIST_TYPES e);
DLL_PUBLIC const char* SYMBOL_DESCRIPTIONS_to_string(enum SYMBOL_DESCRIPTIONS e);

#ifdef __cplusplus
}
#endif


#endif
