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
#ifndef LIEF_PE_ENUM_TO_STRING_H
#define LIEF_PE_ENUM_TO_STRING_H

#include "LIEF/visibility.h"
#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {
DLL_PUBLIC const char* to_string(PE_TYPE e);
DLL_PUBLIC const char* to_string(DATA_DIRECTORY e);

DLL_PUBLIC const char* to_string(MACHINE_TYPES e);
DLL_PUBLIC const char* to_string(HEADER_CHARACTERISTICS e);
DLL_PUBLIC const char* to_string(SUBSYSTEM e);
DLL_PUBLIC const char* to_string(DLL_CHARACTERISTICS e);

DLL_PUBLIC const char* to_string(SECTION_CHARACTERISTICS e);
DLL_PUBLIC const char* to_string(PE_SECTION_TYPES e);

DLL_PUBLIC const char* to_string(SYMBOL_BASE_TYPES e);
DLL_PUBLIC const char* to_string(SYMBOL_COMPLEX_TYPES e);
DLL_PUBLIC const char* to_string(SYMBOL_SECTION_NUMBER e);
DLL_PUBLIC const char* to_string(SYMBOL_STORAGE_CLASS e);

DLL_PUBLIC const char* to_string(RELOCATIONS_BASE_TYPES e);
DLL_PUBLIC const char* to_string(RELOCATIONS_I386 e);
DLL_PUBLIC const char* to_string(RELOCATIONS_AMD64 e);
DLL_PUBLIC const char* to_string(RELOCATIONS_ARM e);

DLL_PUBLIC const char* to_string(DEBUG_TYPES e);

DLL_PUBLIC const char* to_string(RESOURCE_TYPES e);
DLL_PUBLIC const char* to_string(RESOURCE_LANGS e);
DLL_PUBLIC const char* to_string(RESOURCE_SUBLANGS e);
DLL_PUBLIC const char* to_string(CODE_PAGES e);

DLL_PUBLIC const char* to_string(EXTENDED_WINDOW_STYLES e);
DLL_PUBLIC const char* to_string(WINDOW_STYLES e);
DLL_PUBLIC const char* to_string(DIALOG_BOX_STYLES e);

DLL_PUBLIC const char* to_string(FIXED_VERSION_OS e);
DLL_PUBLIC const char* to_string(FIXED_VERSION_FILE_FLAGS e);
DLL_PUBLIC const char* to_string(FIXED_VERSION_FILE_TYPES e);
DLL_PUBLIC const char* to_string(FIXED_VERSION_FILE_SUB_TYPES e);

DLL_PUBLIC const char* to_string(WIN_VERSION e);

DLL_PUBLIC const char* to_string(GUARD_CF_FLAGS e);
DLL_PUBLIC const char* to_string(GUARD_RF_FLAGS e);

} // namespace PE
} // namespace LIEF
#endif


