/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_MACHO_ENUM_TO_STRING_H
#define LIEF_MACHO_ENUM_TO_STRING_H
#include "LIEF/visibility.h"

#include "LIEF/MachO/enums.hpp"
#include "LIEF/MachO/DataCodeEntry.hpp"
#include "LIEF/MachO/BuildVersion.hpp"

namespace LIEF {
namespace MachO {

LIEF_API const char* to_string(LOAD_COMMAND_TYPES e);
LIEF_API const char* to_string(MACHO_TYPES e);
LIEF_API const char* to_string(FILE_TYPES e);
LIEF_API const char* to_string(CPU_TYPES e);
LIEF_API const char* to_string(HEADER_FLAGS e);
LIEF_API const char* to_string(MACHO_SECTION_TYPES e);
LIEF_API const char* to_string(MACHO_SECTION_FLAGS e);
LIEF_API const char* to_string(MACHO_SYMBOL_TYPES e);
LIEF_API const char* to_string(N_LIST_TYPES e);
LIEF_API const char* to_string(SYMBOL_DESCRIPTIONS e);

LIEF_API const char* to_string(X86_RELOCATION e);
LIEF_API const char* to_string(X86_64_RELOCATION e);
LIEF_API const char* to_string(PPC_RELOCATION e);
LIEF_API const char* to_string(ARM_RELOCATION e);
LIEF_API const char* to_string(ARM64_RELOCATION e);
LIEF_API const char* to_string(RELOCATION_ORIGINS e);

LIEF_API const char* to_string(REBASE_TYPES e);
LIEF_API const char* to_string(BINDING_CLASS e);
LIEF_API const char* to_string(REBASE_OPCODES e);
LIEF_API const char* to_string(BIND_TYPES e);
LIEF_API const char* to_string(BIND_SPECIAL_DYLIB e);
LIEF_API const char* to_string(BIND_SUBOPCODE_THREADED e);
LIEF_API const char* to_string(BIND_OPCODES e);
LIEF_API const char* to_string(EXPORT_SYMBOL_KINDS e);
LIEF_API const char* to_string(VM_PROTECTIONS e);
LIEF_API const char* to_string(SYMBOL_ORIGINS e);
LIEF_API const char* to_string(EXPORT_SYMBOL_FLAGS e);
LIEF_API const char* to_string(DataCodeEntry::TYPES e);
LIEF_API const char* to_string(BuildVersion::PLATFORMS e);
LIEF_API const char* to_string(BuildToolVersion::TOOLS e);
LIEF_API const char* to_string(DYLD_CHAINED_PTR_FORMAT e);
LIEF_API const char* to_string(DYLD_CHAINED_FORMAT e);


} // namespace MachO
} // namespace LIEF

#endif
