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
#include "LIEF/ELF/EnumToString.h"
#include "LIEF/ELF/EnumToString.hpp"

#include "LIEF/ELF/enums.h"
#include "LIEF/ELF/enums.hpp"

extern "C"
{
  const char* E_TYPE_to_string(enum LIEF_ELF_E_TYPE e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::E_TYPE>(e));
  }

  const char* SYMBOL_BINDINGS_to_string(enum LIEF_ELF_SYMBOL_BINDINGS e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::SYMBOL_BINDINGS>(e));
  }

  const char* VERSION_to_string(enum LIEF_ELF_VERSION e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::VERSION>(e));
  }

  const char* ARCH_to_string(enum LIEF_ELF_ARCH e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::ARCH>(e));
  }

  const char* SEGMENT_TYPES_to_string(enum LIEF_ELF_SEGMENT_TYPES e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::SEGMENT_TYPES>(e));
  }

  const char* DYNAMIC_TAGS_to_string(enum LIEF_ELF_DYNAMIC_TAGS e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::DYNAMIC_TAGS>(e));
  }

  const char* ELF_SECTION_TYPES_to_string(enum LIEF_ELF_ELF_SECTION_TYPES e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::ELF_SECTION_TYPES>(e));
  }

  const char* ELF_SECTION_FLAGS_to_string(enum LIEF_ELF_ELF_SECTION_FLAGS e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::ELF_SECTION_FLAGS>(e));
  }

  const char* ELF_SYMBOL_TYPES_to_string(enum LIEF_ELF_ELF_SYMBOL_TYPES e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::ELF_SYMBOL_TYPES>(e));
  }

  const char* ELF_CLASS_to_string(enum LIEF_ELF_ELF_CLASS e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::ELF_CLASS>(e));
  }

  const char* ELF_DATA_to_string(enum LIEF_ELF_ELF_DATA e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::ELF_DATA>(e));
  }

  const char* OS_ABI_to_string(enum LIEF_ELF_OS_ABI e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::OS_ABI>(e));
  }

  const char* DYNAMIC_FLAGS_to_string(enum LIEF_ELF_DYNAMIC_FLAGS e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::DYNAMIC_FLAGS>(e));
  }

  const char* DYNAMIC_FLAGS_1_to_string(enum LIEF_ELF_DYNAMIC_FLAGS_1 e) {
    return LIEF::ELF::to_string(static_cast<LIEF::ELF::DYNAMIC_FLAGS_1>(e));
  }

}
