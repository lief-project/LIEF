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

DLL_PUBLIC const char* SYMBOL_BINDINGS_to_string(enum SYMBOL_BINDINGS e);
DLL_PUBLIC const char* E_TYPE_to_string(enum E_TYPE e);
DLL_PUBLIC const char* VERSION_to_string(enum VERSION e);
DLL_PUBLIC const char* ARCH_to_string(enum ARCH e);
DLL_PUBLIC const char* SEGMENT_TYPES_to_string(enum SEGMENT_TYPES e);
DLL_PUBLIC const char* DYNAMIC_TAGS_to_string(enum DYNAMIC_TAGS e);
DLL_PUBLIC const char* ELF_SECTION_TYPES_to_string(enum ELF_SECTION_TYPES e);
DLL_PUBLIC const char* ELF_SECTION_FLAGS_to_string(enum ELF_SECTION_FLAGS e);
DLL_PUBLIC const char* ELF_SYMBOL_TYPES_to_string(enum ELF_SYMBOL_TYPES e);
DLL_PUBLIC const char* ELF_CLASS_to_string(enum ELF_CLASS e);
DLL_PUBLIC const char* ELF_DATA_to_string(enum ELF_DATA e);
DLL_PUBLIC const char* OS_ABI_to_string(enum OS_ABI e);
DLL_PUBLIC const char* DYNAMIC_FLAGS_to_string(enum DYNAMIC_FLAGS e);
DLL_PUBLIC const char* DYNAMIC_FLAGS_1_to_string(enum DYNAMIC_FLAGS_1 e);

#ifdef __cplusplus
}
#endif


#endif
