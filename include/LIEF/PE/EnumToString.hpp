/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include <cstdint>
#include <cstddef>

#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {

enum SYMBOL_SECTION_NUMBER : int;
enum SYMBOL_STORAGE_CLASS : int;
enum class ACCELERATOR_FLAGS : size_t;
enum class ACCELERATOR_VK_CODES : size_t;
enum class ALGORITHMS;
enum class CODE_PAGES : size_t;
enum class CODE_VIEW_SIGNATURES : size_t;
enum class DATA_DIRECTORY : size_t;
enum class DEBUG_TYPES : size_t;
enum class DIALOG_BOX_STYLES : size_t;
enum class DLL_CHARACTERISTICS : size_t;
enum class EXTENDED_WINDOW_STYLES : size_t;
enum class FIXED_VERSION_FILE_FLAGS : size_t;
enum class FIXED_VERSION_FILE_SUB_TYPES : size_t;
enum class FIXED_VERSION_FILE_TYPES : size_t;
enum class FIXED_VERSION_OS : size_t;
enum class GUARD_CF_FLAGS : size_t;
enum class HEADER_CHARACTERISTICS : size_t;
enum class MACHINE_TYPES : size_t;
enum class PE_SECTION_TYPES : uint8_t;
enum class PE_TYPE : uint16_t;
enum class POGO_SIGNATURES : size_t;
enum class RELOCATIONS_AMD64 : size_t;
enum class RELOCATIONS_ARM : size_t;
enum class RELOCATIONS_BASE_TYPES : size_t;
enum class RELOCATIONS_I386 : size_t;
enum class RESOURCE_LANGS : size_t;
enum class RESOURCE_SUBLANGS : size_t;
enum class RESOURCE_TYPES : size_t;
enum class SECTION_CHARACTERISTICS : size_t;
enum class SIG_ATTRIBUTE_TYPES;
enum class SUBSYSTEM : size_t;
enum class SYMBOL_BASE_TYPES : size_t;
enum class SYMBOL_COMPLEX_TYPES : size_t;
enum class WINDOW_STYLES : size_t;
enum class WIN_VERSION : size_t;

LIEF_API const char* to_string(PE_TYPE e);
LIEF_API const char* to_string(DATA_DIRECTORY e);

LIEF_API const char* to_string(MACHINE_TYPES e);
LIEF_API const char* to_string(HEADER_CHARACTERISTICS e);
LIEF_API const char* to_string(SUBSYSTEM e);
LIEF_API const char* to_string(DLL_CHARACTERISTICS e);

LIEF_API const char* to_string(SECTION_CHARACTERISTICS e);
LIEF_API const char* to_string(PE_SECTION_TYPES e);

LIEF_API const char* to_string(SYMBOL_BASE_TYPES e);
LIEF_API const char* to_string(SYMBOL_COMPLEX_TYPES e);
LIEF_API const char* to_string(SYMBOL_SECTION_NUMBER e);
LIEF_API const char* to_string(SYMBOL_STORAGE_CLASS e);

LIEF_API const char* to_string(RELOCATIONS_BASE_TYPES e);
LIEF_API const char* to_string(RELOCATIONS_I386 e);
LIEF_API const char* to_string(RELOCATIONS_AMD64 e);
LIEF_API const char* to_string(RELOCATIONS_ARM e);

LIEF_API const char* to_string(DEBUG_TYPES e);
LIEF_API const char* to_string(CODE_VIEW_SIGNATURES e);
LIEF_API const char* to_string(POGO_SIGNATURES e);

LIEF_API const char* to_string(RESOURCE_TYPES e);
LIEF_API const char* to_string(RESOURCE_LANGS e);
LIEF_API const char* to_string(RESOURCE_SUBLANGS e);
LIEF_API const char* to_string(CODE_PAGES e);

LIEF_API const char* to_string(EXTENDED_WINDOW_STYLES e);
LIEF_API const char* to_string(WINDOW_STYLES e);
LIEF_API const char* to_string(DIALOG_BOX_STYLES e);

LIEF_API const char* to_string(FIXED_VERSION_OS e);
LIEF_API const char* to_string(FIXED_VERSION_FILE_FLAGS e);
LIEF_API const char* to_string(FIXED_VERSION_FILE_TYPES e);
LIEF_API const char* to_string(FIXED_VERSION_FILE_SUB_TYPES e);

LIEF_API const char* to_string(WIN_VERSION e);

LIEF_API const char* to_string(GUARD_CF_FLAGS e);

LIEF_API const char* to_string(ACCELERATOR_FLAGS e);
LIEF_API const char* to_string(ACCELERATOR_VK_CODES e);

LIEF_API const char* to_string(ALGORITHMS e);
LIEF_API const char* to_string(SIG_ATTRIBUTE_TYPES e);

} // namespace PE
} // namespace LIEF
#endif


