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
#include <iomanip>

#include "LIEF/exception.hpp"
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/EnumToString.hpp"

#include "RelocationSizes.hpp"
#include "LIEF/logging++.hpp"

namespace LIEF {
namespace ELF {

Relocation::~Relocation(void) = default;

Relocation::Relocation(void) :
  LIEF::Relocation{},
  type_{0},
  addend_{0},
  isRela_{false},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{}


Relocation::Relocation(const Relocation& other) :
  LIEF::Relocation{other},
  type_{other.type_},
  addend_{other.addend_},
  isRela_{other.isRela_},
  symbol_{nullptr},
  architecture_{other.architecture_},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{
}


Relocation& Relocation::operator=(Relocation other) {
  this->swap(other);
  return *this;
}

Relocation::Relocation(const Elf32_Rel* header) :
  LIEF::Relocation{header->r_offset, 0},
  type_{static_cast<uint32_t>(header->r_info & 0xff)},
  addend_{0},
  isRela_{false},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{}


Relocation::Relocation(const Elf32_Rela* header) :
  LIEF::Relocation{header->r_offset, 0},
  type_{static_cast<uint32_t>(header->r_info & 0xff)},
  addend_{header->r_addend},
  isRela_{true},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{}


Relocation::Relocation(const Elf64_Rel* header) :
  LIEF::Relocation{header->r_offset, 0},
  type_{static_cast<uint32_t>(header->r_info & 0xffffffff)},
  addend_{0},
  isRela_{false},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{}


Relocation::Relocation(const Elf64_Rela* header)  :
  LIEF::Relocation{header->r_offset, 0},
  type_{static_cast<uint32_t>(header->r_info & 0xffffffff)},
  addend_{header->r_addend},
  isRela_{true},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{}


Relocation::Relocation(uint64_t address, uint32_t type, int64_t addend, bool isRela) :
  LIEF::Relocation{address, 0},
  type_{type},
  addend_{addend},
  isRela_{isRela},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE},
  purpose_{RELOCATION_PURPOSES::RELOC_PURPOSE_NONE},
  section_{nullptr}
{}


void Relocation::swap(Relocation& other) {
  std::swap(this->address_,      other.address_);
  std::swap(this->type_,         other.type_);
  std::swap(this->addend_,       other.addend_);
  std::swap(this->isRela_,       other.isRela_);
  std::swap(this->symbol_,       other.symbol_);
  std::swap(this->architecture_, other.architecture_);
  std::swap(this->purpose_,      other.purpose_);
  std::swap(this->section_,      other.section_);
}

int64_t Relocation::addend(void) const {
  return this->addend_;
}


uint32_t Relocation::type(void) const {
  return this->type_;
}


const Symbol& Relocation::symbol(void) const {
  if (this->symbol_ != nullptr) {
    return *this->symbol_;
  } else {
    throw not_found("No symbol associated with this relocation");
  }
}

Symbol& Relocation::symbol(void) {
  return const_cast<Symbol&>(static_cast<const Relocation*>(this)->symbol());
}

const Section& Relocation::section(void) const {
  if (this->has_section()) {
    return *this->section_;
  } else {
    throw not_found("No section associated with this relocation");
  }
}

Section& Relocation::section(void) {
  return const_cast<Section&>(static_cast<const Relocation*>(this)->section());
}

bool Relocation::is_rela(void) const {
  return this->isRela_;
}


bool Relocation::is_rel(void) const {
  return not this->isRela_;
}


ARCH Relocation::architecture(void) const {
  return this->architecture_;
}


RELOCATION_PURPOSES Relocation::purpose(void) const {
  return this->purpose_;
}


bool Relocation::has_symbol(void) const {
  return this->symbol_ != nullptr;
}

bool Relocation::has_section(void) const {
  return this->section_ != nullptr;
}

size_t Relocation::size(void) const {

 switch (this->architecture()) {
    case ARCH::EM_X86_64:
      {
        auto&& it = relocation_x86_64_sizes.find(static_cast<RELOC_x86_64>(this->type()));
        if (it == std::end(relocation_x86_64_sizes)) {
          LOG(ERROR) << to_string(this->architecture()) << std::string(" - ") << to_string(static_cast<RELOC_x86_64>(this->type()));
          return -1u;
        }
        return it->second;
      }

    case ARCH::EM_386:
      {
        auto&& it = relocation_i386_sizes.find(static_cast<RELOC_i386>(this->type()));
        if (it == std::end(relocation_i386_sizes)) {
          LOG(ERROR) << to_string(this->architecture()) << std::string(" - ") << to_string(static_cast<RELOC_i386>(this->type()));
          return -1u;
        }
        return it->second;
      }

    case ARCH::EM_ARM:
      {
        auto&& it = relocation_ARM_sizes.find(static_cast<RELOC_ARM>(this->type()));
        if (it == std::end(relocation_ARM_sizes)) {
          LOG(ERROR) << to_string(this->architecture()) << std::string(" - ") << to_string(static_cast<RELOC_ARM>(this->type()));
          return -1u;
        }
        return it->second;
      }

    case ARCH::EM_AARCH64:
      {
        auto&& it = relocation_AARCH64_sizes.find(static_cast<RELOC_AARCH64>(this->type()));
        if (it == std::end(relocation_AARCH64_sizes)) {
          LOG(ERROR) << to_string(this->architecture()) << std::string(" - ") << to_string(static_cast<RELOC_AARCH64>(this->type()));
          return -1u;
        }
        return it->second;
      }

    case ARCH::EM_PPC:
      {
        auto&& it = relocation_PPC_sizes.find(static_cast<RELOC_POWERPC32>(this->type()));
        if (it == std::end(relocation_PPC_sizes)) {
          LOG(ERROR) << to_string(this->architecture()) << std::string(" - ") << to_string(static_cast<RELOC_POWERPC32>(this->type()));
          return -1u;
        }
        return it->second;
      }

    case ARCH::EM_PPC64:
      {
        auto&& it = relocation_PPC64_sizes.find(static_cast<RELOC_POWERPC64>(this->type()));
        if (it == std::end(relocation_PPC64_sizes)) {
          LOG(ERROR) << to_string(this->architecture()) << std::string(" - ") << to_string(static_cast<RELOC_POWERPC64>(this->type()));
          return -1u;
        }
        return it->second;
      }

    default:
      {
        LOG(ERROR) << to_string(this->architecture()) << " not implemented";
        return -1u;
      }
  }

}


void Relocation::addend(int64_t addend) {
  this->addend_ = addend;
}


void Relocation::type(uint32_t type) {
  this->type_ = type;
}


void Relocation::purpose(RELOCATION_PURPOSES purpose) {
  this->purpose_ = purpose;
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Relocation::operator==(const Relocation& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Relocation::operator!=(const Relocation& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const Relocation& entry) {
  std::string symbol_name = "";
  os << std::hex;
  os << std::left;

  if (entry.has_symbol()) {
    const Symbol& symbol = entry.symbol();
    try {
      symbol_name = symbol.demangled_name();
    } catch (const not_supported&) {
      symbol_name = symbol.name();
    }
  }

  std::string relocation_type = "";
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
     << std::setw(8) << std::hex << entry.addend()
     << std::setw(10) << to_string(entry.purpose())
     << std::setw(10) << symbol_name;

  return os;
}
}
}
