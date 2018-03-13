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
#ifndef C_LIEF_ELF_ENUM_TO_STRING_H_
#define C_LIEF_ELF_ENUM_TO_STRING_H_

#include "LIEF/visibility.h"

#include "LIEF/ELF/enums.h"

#ifdef __cplusplus
extern "C" {
#endif

LIEF_API const char* SYMBOL_BINDINGS_to_string(enum LIEF_ELF_SYMBOL_BINDINGS e);
LIEF_API const char* E_TYPE_to_string(enum LIEF_ELF_E_TYPE e);
LIEF_API const char* VERSION_to_string(enum LIEF_ELF_VERSION e);
LIEF_API const char* ARCH_to_string(enum LIEF_ELF_ARCH e);
LIEF_API const char* SEGMENT_TYPES_to_string(enum LIEF_ELF_SEGMENT_TYPES e);
LIEF_API const char* DYNAMIC_TAGS_to_string(enum LIEF_ELF_DYNAMIC_TAGS e);
LIEF_API const char* ELF_SECTION_TYPES_to_string(enum LIEF_ELF_ELF_SECTION_TYPES e);
LIEF_API const char* ELF_SECTION_FLAGS_to_string(enum LIEF_ELF_ELF_SECTION_FLAGS e);
LIEF_API const char* ELF_SYMBOL_TYPES_to_string(enum LIEF_ELF_ELF_SYMBOL_TYPES e);
LIEF_API const char* ELF_CLASS_to_string(enum LIEF_ELF_ELF_CLASS e);
LIEF_API const char* ELF_DATA_to_string(enum LIEF_ELF_ELF_DATA e);
LIEF_API const char* OS_ABI_to_string(enum LIEF_ELF_OS_ABI e);
LIEF_API const char* DYNAMIC_FLAGS_to_string(enum LIEF_ELF_DYNAMIC_FLAGS e);
LIEF_API const char* DYNAMIC_FLAGS_1_to_string(enum LIEF_ELF_DYNAMIC_FLAGS_1 e);

#ifdef __cplusplus
}
#endif


#endif
