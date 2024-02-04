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
enum class ALGORITHMS : uint32_t;
enum class CODE_PAGES : size_t;
enum class DIALOG_BOX_STYLES : size_t;
enum class EXTENDED_WINDOW_STYLES : size_t;
enum class FIXED_VERSION_FILE_FLAGS : size_t;
enum class FIXED_VERSION_FILE_SUB_TYPES : size_t;
enum class FIXED_VERSION_FILE_TYPES : size_t;
enum class FIXED_VERSION_OS : size_t;
enum class PE_SECTION_TYPES : uint8_t;
enum class PE_TYPE : uint16_t;
enum class RELOCATIONS_AMD64 : size_t;
enum class RELOCATIONS_ARM : size_t;
enum class RELOCATIONS_BASE_TYPES : size_t;
enum class RELOCATIONS_I386 : size_t;
enum class SUBSYSTEM : size_t;
enum class SYMBOL_BASE_TYPES : size_t;
enum class SYMBOL_COMPLEX_TYPES : size_t;
enum class WINDOW_STYLES : size_t;

LIEF_API const char* to_string(PE_TYPE e);

LIEF_API const char* to_string(PE_SECTION_TYPES e);

LIEF_API const char* to_string(SYMBOL_BASE_TYPES e);
LIEF_API const char* to_string(SYMBOL_COMPLEX_TYPES e);
LIEF_API const char* to_string(SYMBOL_SECTION_NUMBER e);
LIEF_API const char* to_string(SYMBOL_STORAGE_CLASS e);

LIEF_API const char* to_string(RELOCATIONS_BASE_TYPES e);
LIEF_API const char* to_string(RELOCATIONS_I386 e);
LIEF_API const char* to_string(RELOCATIONS_AMD64 e);
LIEF_API const char* to_string(RELOCATIONS_ARM e);

LIEF_API const char* to_string(CODE_PAGES e);

LIEF_API const char* to_string(EXTENDED_WINDOW_STYLES e);
LIEF_API const char* to_string(WINDOW_STYLES e);
LIEF_API const char* to_string(DIALOG_BOX_STYLES e);

LIEF_API const char* to_string(FIXED_VERSION_OS e);
LIEF_API const char* to_string(FIXED_VERSION_FILE_FLAGS e);
LIEF_API const char* to_string(FIXED_VERSION_FILE_TYPES e);
LIEF_API const char* to_string(FIXED_VERSION_FILE_SUB_TYPES e);

LIEF_API const char* to_string(ACCELERATOR_FLAGS e);
LIEF_API const char* to_string(ACCELERATOR_VK_CODES e);

LIEF_API const char* to_string(ALGORITHMS e);

} // namespace PE
} // namespace LIEF
#endif


