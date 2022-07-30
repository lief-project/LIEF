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
#include <iomanip>
#include <climits>

#include "LIEF/exception.hpp"
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/Symbol.hpp"

#include "LIEF/ELF/RelocationSizes.hpp"
#include "ELF/Structures.hpp"

#include "logging.hpp"

namespace LIEF {
namespace ELF {

Relocation::~Relocation() = default;
Relocation::Relocation() = default;

Relocation::Relocation(const Relocation& other) :
  LIEF::Relocation{other},
  type_{other.type_},
  addend_{other.addend_},
  isRela_{other.isRela_},
  architecture_{other.architecture_}
{}


Relocation::Relocation(ARCH arch) {
  architecture_ = arch;
}


Relocation& Relocation::operator=(Relocation other) {
  swap(other);
  return *this;
}

Relocation::Relocation(const details::Elf32_Rel& header) :
  LIEF::Relocation{header.r_offset, 0},
  type_{static_cast<uint32_t>(header.r_info & 0xff)},
  info_{static_cast<uint32_t>(header.r_info >> 8)}
{}


Relocation::Relocation(const details::Elf32_Rela& header) :
  LIEF::Relocation{header.r_offset, 0},
  type_{static_cast<uint32_t>(header.r_info & 0xff)},
  addend_{header.r_addend},
  isRela_{true},
  info_{static_cast<uint32_t>(header.r_info >> 8)}
{}


Relocation::Relocation(const details::Elf64_Rel& header) :
  LIEF::Relocation{header.r_offset, 0},
  type_{static_cast<uint32_t>(header.r_info & 0xffffffff)},
  info_{static_cast<uint32_t>(header.r_info >> 32)}
{}


Relocation::Relocation(const details::Elf64_Rela& header)  :
  LIEF::Relocation{header.r_offset, 0},
  type_{static_cast<uint32_t>(header.r_info & 0xffffffff)},
  addend_{header.r_addend},
  isRela_{true},
  info_{static_cast<uint32_t>(header.r_info >> 32)}
{}


Relocation::Relocation(uint64_t address, uint32_t type, int64_t addend, bool isRela) :
  LIEF::Relocation{address, 0},
  type_{type},
  addend_{addend},
  isRela_{isRela}
{}


void Relocation::swap(Relocation& other) {
  std::swap(address_,      other.address_);
  std::swap(type_,         other.type_);
  std::swap(addend_,       other.addend_);
  std::swap(isRela_,       other.isRela_);
  std::swap(symbol_,       other.symbol_);
  std::swap(architecture_, other.architecture_);
  std::swap(purpose_,      other.purpose_);
  std::swap(section_,      other.section_);
  std::swap(info_,         other.info_);
}

int64_t Relocation::addend() const {
  return addend_;
}


uint32_t Relocation::type() const {
  return type_;
}


const Symbol* Relocation::symbol() const {
  return symbol_;
}

Symbol* Relocation::symbol() {
  return const_cast<Symbol*>(static_cast<const Relocation*>(this)->symbol());
}

const Section* Relocation::section() const {
  return section_;
}

Section* Relocation::section() {
  return const_cast<Section*>(static_cast<const Relocation*>(this)->section());
}

bool Relocation::is_rela() const {
  return isRela_;
}


bool Relocation::is_rel() const {
  return !isRela_;
}


ARCH Relocation::architecture() const {
  return architecture_;
}


RELOCATION_PURPOSES Relocation::purpose() const {
  return purpose_;
}


bool Relocation::has_symbol() const {
  return symbol_ != nullptr;
}

bool Relocation::has_section() const {
  return section_ != nullptr;
}

uint32_t Relocation::info() const {
  return info_;
}

size_t Relocation::size() const {

 switch (architecture()) {
    case ARCH::EM_X86_64:
      {
        const auto it = relocation_x86_64_sizes.find(static_cast<RELOC_x86_64>(type()));
        if (it == std::end(relocation_x86_64_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_x86_64>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }

    case ARCH::EM_386:
      {
        const auto it = relocation_i386_sizes.find(static_cast<RELOC_i386>(type()));
        if (it == std::end(relocation_i386_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_i386>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }

    case ARCH::EM_ARM:
      {
        const auto it = relocation_ARM_sizes.find(static_cast<RELOC_ARM>(type()));
        if (it == std::end(relocation_ARM_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_ARM>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }

    case ARCH::EM_AARCH64:
      {
        const auto it = relocation_AARCH64_sizes.find(static_cast<RELOC_AARCH64>(type()));
        if (it == std::end(relocation_AARCH64_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_AARCH64>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }

    case ARCH::EM_MIPS:
      {
        const auto it = relocation_MIPS_sizes.find(static_cast<RELOC_MIPS>(type()));
        if (it == std::end(relocation_MIPS_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_MIPS>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }


    case ARCH::EM_PPC:
      {
        const auto it = relocation_PPC_sizes.find(static_cast<RELOC_POWERPC32>(type()));
        if (it == std::end(relocation_PPC_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_POWERPC32>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }

    case ARCH::EM_PPC64:
      {
        const auto it = relocation_PPC64_sizes.find(static_cast<RELOC_POWERPC64>(type()));
        if (it == std::end(relocation_PPC64_sizes)) {
          LIEF_ERR("{} - {}", to_string(architecture()), to_string(static_cast<RELOC_POWERPC64>(type())));
          return SIZE_MAX;
        }
        return it->second;
      }

    default:
      {
        LIEF_ERR("Architecture {} not implemented", to_string(architecture()));
        return SIZE_MAX;
      }
  }

}


void Relocation::addend(int64_t addend) {
  addend_ = addend;
}


void Relocation::type(uint32_t type) {
  type_ = type;
}

void Relocation::info(uint32_t v) {
  info_ = v;
}

void Relocation::symbol(Symbol* sym) {
  symbol_ = sym;
}

void Relocation::section(Section* section) {
  section_ = section;
}


void Relocation::purpose(RELOCATION_PURPOSES purpose) {
  purpose_ = purpose;
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Relocation::operator==(const Relocation& rhs) const {
  if (this == &rhs) {
    return true;
  }

  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Relocation& entry) {
  std::string symbol_name;
  os << std::hex;
  os << std::left;

  const Symbol* symbol = entry.symbol();
  if (symbol != nullptr) {
    symbol_name = symbol->demangled_name();
    if (symbol_name.empty()) {
      symbol_name = symbol->name();
    }
  }

  std::string relocation_type;
  switch (entry.architecture()) {
    case ARCH::EM_X86_64:
      {
        relocation_type = to_string(static_cast<RELOC_x86_64>(entry.type()));
        break;
      }

    case ARCH::EM_386:
      {
        relocation_type = to_string(static_cast<RELOC_i386>(entry.type()));
        break;
      }

    case ARCH::EM_ARM:
      {
        relocation_type = to_string(static_cast<RELOC_ARM>(entry.type()));
        break;
      }

    case ARCH::EM_AARCH64:
      {
        relocation_type = to_string(static_cast<RELOC_AARCH64>(entry.type()));
        break;
      }

    case ARCH::EM_MIPS:
      {
        relocation_type = to_string(static_cast<RELOC_MIPS>(entry.type()));
        break;
      }

    case ARCH::EM_PPC:
      {
        relocation_type = to_string(static_cast<RELOC_POWERPC32>(entry.type()));
        break;
      }

    case ARCH::EM_PPC64:
      {
        relocation_type = to_string(static_cast<RELOC_POWERPC64>(entry.type()));
        break;
      }

    default:
      {
        relocation_type = std::to_string(entry.type());
      }
  }



  os << std::setw(10) << entry.address()
     << std::setw(10) << relocation_type
     << std::setw(4) << std::dec << entry.size()
     << std::setw(10) << std::hex << entry.addend()
     << std::setw(10) << std::hex << entry.info()
     << std::setw(10) << to_string(entry.purpose())
     << std::setw(10) << symbol_name;

  return os;
}
}
}
