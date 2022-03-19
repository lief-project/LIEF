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
#include "LIEF/PE/EnumToString.h"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/enums.h"
#include "LIEF/PE/enums.hpp"

extern "C" {

const char* PE_TYPES_to_string(enum LIEF_PE_PE_TYPES e) {
  return LIEF::PE::to_string(static_cast<LIEF::PE::PE_TYPE>(e));
}

const char* MACHINE_TYPES_to_string(enum LIEF_PE_MACHINE_TYPES e) {
  return LIEF::PE::to_string(static_cast<LIEF::PE::MACHINE_TYPES>(e));
}

const char* SUBSYSTEM_to_string(enum LIEF_PE_SUBSYSTEM e) {
  return LIEF::PE::to_string(static_cast<LIEF::PE::SUBSYSTEM>(e));
}
}
