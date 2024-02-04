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
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Symbol.hpp"

#include "ELF/Structures.hpp"

#include "logging.hpp"

namespace LIEF {
namespace ELF {

int32_t get_reloc_size(Relocation::TYPE type);

Relocation::TYPE Relocation::type_from(uint32_t value, ARCH arch) {
  switch (arch) {
    case ARCH::X86_64:
      return TYPE(value | R_X64);
    case ARCH::AARCH64:
      return TYPE(value | R_AARCH64);
    case ARCH::I386:
      return TYPE(value | R_X86);
    case ARCH::ARM:
      return TYPE(value | R_ARM);
    case ARCH::HEXAGON:
      return TYPE(value | R_HEXAGON);
    case ARCH::LOONGARCH:
      return TYPE(value | R_LARCH);
    case ARCH::MIPS:
      return TYPE(value | R_MIPS);
    case ARCH::PPC:
      return TYPE(value | R_PPC);
    case ARCH::PPC64:
      return TYPE(value | R_PPC64);
    case ARCH::SPARC:
      return TYPE(value | R_SPARC);
    default:
      {
        LIEF_ERR("LIEF does not support relocation for '{}'", to_string(arch));
        return TYPE::UNKNOWN;
      }
  }
  return TYPE::UNKNOWN;
}

Relocation::Relocation(const Relocation& other) :
  LIEF::Relocation{other},
  type_{other.type_},
  addend_{other.addend_},
  encoding_{other.encoding_},
  architecture_{other.architecture_}
{}

Relocation& Relocation::operator=(Relocation other) {
  swap(other);
  return *this;
}

template<class T>
Relocation::Relocation(const T& header, PURPOSE purpose, ENCODING enc, ARCH arch) :
  LIEF::Relocation{header.r_offset, 0},
  encoding_{enc},
  architecture_{arch},
  purpose_{purpose}
{
  if constexpr (std::is_same_v<T, details::Elf32_Rel> ||
                std::is_same_v<T, details::Elf32_Rela>)
  {
    type_ = type_from(header.r_info & 0xff, arch);
    info_ = static_cast<uint32_t>(header.r_info >> 8);
  }

  if constexpr (std::is_same_v<T, details::Elf64_Rel> ||
                std::is_same_v<T, details::Elf64_Rela>)
  {
    type_ = type_from(header.r_info & 0xffffffff, arch);
    info_ = static_cast<uint32_t>(header.r_info >> 32);
  }

  if constexpr (std::is_same_v<T, details::Elf32_Rela> ||
                std::is_same_v<T, details::Elf64_Rela>)
  {
    addend_ = header.r_addend;
  }
}

Relocation::Relocation(uint64_t address, TYPE type, ENCODING encoding) :
  LIEF::Relocation(address, 0),
  type_(type),
  encoding_(encoding)
{
  if (type != TYPE::UNKNOWN) {
    auto raw_type = static_cast<uint64_t>(type);
    const uint64_t ID = (raw_type >> Relocation::R_BIT) << Relocation::R_BIT;
    if (ID == Relocation::R_X64) {
      architecture_ = ARCH::X86_64;
    }
    else if (ID == Relocation::R_AARCH64) {
      architecture_ = ARCH::AARCH64;
    }
    else if (ID == Relocation::R_ARM) {
      architecture_ = ARCH::ARM;
    }
    else if (ID == Relocation::R_HEXAGON) {
      architecture_ = ARCH::HEXAGON;
    }
    else if (ID == Relocation::R_X86) {
      architecture_ = ARCH::I386;
    }
    else if (ID == Relocation::R_LARCH) {
      architecture_ = ARCH::LOONGARCH;
    }
    else if (ID == Relocation::R_MIPS) {
      architecture_ = ARCH::MIPS;
    }
    else if (ID == Relocation::R_PPC) {
      architecture_ = ARCH::PPC;
    }
    else if (ID == Relocation::R_PPC64) {
      architecture_ = ARCH::PPC64;
    }
    else if (ID == Relocation::R_SPARC) {
      architecture_ = ARCH::SPARC;
    }
  }
}

template Relocation::Relocation(const details::Elf32_Rel&, PURPOSE, ENCODING, ARCH);
template Relocation::Relocation(const details::Elf32_Rela&, PURPOSE, ENCODING, ARCH);
template Relocation::Relocation(const details::Elf64_Rel&, PURPOSE, ENCODING, ARCH);
template Relocation::Relocation(const details::Elf64_Rela&, PURPOSE, ENCODING, ARCH);

void Relocation::swap(Relocation& other) {
  std::swap(address_,      other.address_);
  std::swap(type_,         other.type_);
  std::swap(addend_,       other.addend_);
  std::swap(encoding_,     other.encoding_);
  std::swap(symbol_,       other.symbol_);
  std::swap(architecture_, other.architecture_);
  std::swap(purpose_,      other.purpose_);
  std::swap(section_,      other.section_);
  std::swap(info_,         other.info_);
}

size_t Relocation::size() const {
  return get_reloc_size(type_);
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Relocation& entry) {
  std::string symbol_name;

  if (const Symbol* symbol = entry.symbol()) {
    symbol_name = symbol->demangled_name();
    if (symbol_name.empty()) {
      symbol_name = symbol->name();
    }
  }

  os << fmt::format("0x{:06x} {} ({}) 0x{:04x} 0x{:02x} {}",
                    entry.address(), to_string(entry.type()),
                    entry.size(), entry.addend(), entry.info(), symbol_name);
  return os;
}
}
}
