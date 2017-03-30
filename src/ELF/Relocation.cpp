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
#include "LIEF/visitors/Hash.hpp"

#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/EnumToString.hpp"

namespace LIEF {
namespace ELF {

Relocation::~Relocation(void) = default;

Relocation::Relocation(void) :
  address_{0},
  type_{0},
  addend_{0},
  isRela_{false},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE}
{}


Relocation::Relocation(const Relocation& other) :
  Visitable{other},
  address_{other.address_},
  type_{other.type_},
  addend_{other.addend_},
  isRela_{other.isRela_},
  symbol_{nullptr},
  architecture_{other.architecture_}
{
}


Relocation& Relocation::operator=(Relocation other) {
  this->swap(other);
  return *this;
}

Relocation::Relocation(const Elf32_Rel* header) :
  address_{header->r_offset},
  type_{static_cast<uint32_t>(header->r_info & 0xff)},
  addend_{0},
  isRela_{false},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE}
{}


Relocation::Relocation(const Elf32_Rela* header) :
  address_{header->r_offset},
  type_{static_cast<uint32_t>(header->r_info & 0xff)},
  addend_{header->r_addend},
  isRela_{true},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE}
{}


Relocation::Relocation(const Elf64_Rel* header) :
  address_{header->r_offset},
  type_{static_cast<uint32_t>(header->r_info & 0xffffffff)},
  addend_{0},
  isRela_{false},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE}
{}


Relocation::Relocation(const Elf64_Rela* header)  :
  address_{header->r_offset},
  type_{static_cast<uint32_t>(header->r_info & 0xffffffff)},
  addend_{header->r_addend},
  isRela_{true},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE}
{}


Relocation::Relocation(uint64_t address, uint32_t type, int64_t addend, bool isRela) :
  address_{address},
  type_{type},
  addend_{addend},
  isRela_{isRela},
  symbol_{nullptr},
  architecture_{ARCH::EM_NONE}
{}


void Relocation::swap(Relocation& other) {
  std::swap(this->address_,      other.address_);
  std::swap(this->type_,         other.type_);
  std::swap(this->addend_,       other.addend_);
  std::swap(this->isRela_,       other.isRela_);
  std::swap(this->symbol_,       other.symbol_);
  std::swap(this->architecture_, other.architecture_);
}

uint64_t Relocation::address(void) const {
  return this->address_;
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


bool Relocation::is_rela(void) const {
  return this->isRela_;
}


bool Relocation::is_rel(void) const {
  return not this->isRela_;
}


ARCH Relocation::architecture(void) const {
  return this->architecture_;
}


bool Relocation::has_symbol(void) const {
  return this->symbol_ != nullptr;
}


void Relocation::address(uint64_t address) {
  this->address_ = address;
}


void Relocation::addend(int64_t addend) {
  this->addend_ = addend;
}


void Relocation::type(uint32_t type) {
  this->type_ = type;
}


void Relocation::accept(Visitor& visitor) const {
  visitor.visit(this->address());
  visitor.visit(this->addend());
  visitor.visit(this->type());
  visitor.visit(this->architecture());
  if (this->has_symbol()) {
    visitor(this->symbol());
  }

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
  if (entry.architecture() == ARCH::EM_X86_64) {
    relocation_type = to_string(static_cast<RELOC_x86_64>(entry.type()));
  }

  os << std::setw(10) << entry.address()
     << std::setw(10) << relocation_type
     << std::setw(10) << symbol_name;

  return os;
}
}
}
