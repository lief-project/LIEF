/* Copyright 2021 - 2025 R. Thomas
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
#include "paging.hpp"
#include "Object.tcc"
#include "LIEF/utils.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/AuxiliarySymbol.hpp"

namespace LIEF {

using LIEF::operator""_KB;

static constexpr auto DEFAULT_PAGESZ = 4_KB;

uint32_t get_pagesize(const ELF::Binary&) {
  return 4_KB;
}

uint32_t get_pagesize(const PE::Binary& pe) {
  // According to: https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200
  switch (pe.header().machine()) {
    case PE::Header::MACHINE_TYPES::I386:
    case PE::Header::MACHINE_TYPES::AMD64:
    case PE::Header::MACHINE_TYPES::SH4:
    case PE::Header::MACHINE_TYPES::MIPS16:
    case PE::Header::MACHINE_TYPES::MIPSFPU:
    case PE::Header::MACHINE_TYPES::MIPSFPU16:
    case PE::Header::MACHINE_TYPES::POWERPC:
    case PE::Header::MACHINE_TYPES::THUMB:
    case PE::Header::MACHINE_TYPES::ARM:
    case PE::Header::MACHINE_TYPES::ARMNT:
    case PE::Header::MACHINE_TYPES::ARM64:
      return 4_KB;

    case PE::Header::MACHINE_TYPES::IA64:
      return 8_KB;

    default:
      return DEFAULT_PAGESZ;
  }
  return DEFAULT_PAGESZ;
}


uint32_t get_pagesize(const MachO::Binary& macho) {
  switch (macho.header().cpu_type()) {
    case MachO::Header::CPU_TYPE::X86:
    case MachO::Header::CPU_TYPE::X86_64:
      return 4_KB;

    case MachO::Header::CPU_TYPE::ARM:
    case MachO::Header::CPU_TYPE::ARM64:
      return 16_KB;

    default:
      return DEFAULT_PAGESZ;
  }
  return DEFAULT_PAGESZ;
}

uint32_t get_pagesize(const Binary& bin) {
  if (ELF::Binary::classof(&bin)) {
    return get_pagesize(*bin.as<ELF::Binary>());
  }

  if (PE::Binary::classof(&bin)) {
    return get_pagesize(*bin.as<PE::Binary>());
  }

  if (MachO::Binary::classof(&bin)) {
    return get_pagesize(*bin.as<MachO::Binary>());
  }

  return DEFAULT_PAGESZ;
}
}
