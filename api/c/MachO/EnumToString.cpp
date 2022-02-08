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
#include "LIEF/MachO/EnumToString.h"
#include "LIEF/MachO/EnumToString.hpp"

#include "LIEF/MachO/enums.hpp"
#include "LIEF/MachO/enums.h"


extern "C"
{

const char* LOAD_COMMAND_TYPES_to_string(enum LIEF_MACHO_LOAD_COMMAND_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::LOAD_COMMAND_TYPES>(e));
}


const char* MACHO_TYPES_to_string(enum LIEF_MACHO_MACHO_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::MACHO_TYPES>(e));
}


const char* FILE_TYPES_to_string(enum LIEF_MACHO_FILE_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::FILE_TYPES>(e));
}


const char* CPU_TYPES_to_string(enum LIEF_MACHO_CPU_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::CPU_TYPES>(e));
}


const char* HEADER_FLAGS_to_string(enum LIEF_MACHO_HEADER_FLAGS e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::HEADER_FLAGS>(e));
}


const char* MACHO_SECTION_TYPES_to_string(enum LIEF_MACHO_MACHO_SECTION_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::MACHO_SECTION_TYPES>(e));
}


const char* MACHO_SYMBOL_TYPES_to_string(enum LIEF_MACHO_MACHO_SYMBOL_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::MACHO_SYMBOL_TYPES>(e));
}


const char* N_LIST_TYPES_to_string(enum LIEF_MACHO_N_LIST_TYPES e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::N_LIST_TYPES>(e));
}


const char* SYMBOL_DESCRIPTIONS_to_string(enum LIEF_MACHO_SYMBOL_DESCRIPTIONS e) {
  return LIEF::MachO::to_string(static_cast<LIEF::MachO::SYMBOL_DESCRIPTIONS>(e));
}







}
