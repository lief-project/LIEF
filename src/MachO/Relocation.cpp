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
#include <numeric>
#include <iomanip>

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

Relocation::~Relocation(void) = default;

Relocation::Relocation(void) :
  address_{0},
  symbol_{nullptr},
  is_pcrel_{0},
  size_{0},
  type_{0},
  architecture_{CPU_TYPES::CPU_TYPE_ANY},
  is_scattered_{false},
  value_{0},
  section_{nullptr}
{}

Relocation::Relocation(const relocation_info *relocinfo) :
  address_{static_cast<uint32_t>(relocinfo->r_address)},
  symbol_{nullptr},
  is_pcrel_{static_cast<bool>(relocinfo->r_pcrel)},
  size_{static_cast<uint8_t>(relocinfo->r_length)},
  type_{static_cast<uint8_t>(relocinfo->r_type)},
  architecture_{CPU_TYPES::CPU_TYPE_ANY},
  is_scattered_{false},
  value_{0},
  section_{nullptr}
{
}

Relocation::Relocation(const scattered_relocation_info *scattered_relocinfo) :
  address_{scattered_relocinfo->r_address},
  symbol_{nullptr},
  is_pcrel_{static_cast<bool>(scattered_relocinfo->r_pcrel)},
  size_{static_cast<uint8_t>(scattered_relocinfo->r_length)},
  type_{static_cast<uint8_t>(scattered_relocinfo->r_type)},
  architecture_{CPU_TYPES::CPU_TYPE_ANY},
  is_scattered_{true},
  value_{scattered_relocinfo->r_value},
  section_{nullptr}
{}

Relocation& Relocation::operator=(Relocation other) {
  this->swap(other);
  return *this;
}

Relocation::Relocation(const Relocation& other) :
  address_{other.address_},
  symbol_{nullptr},
  is_pcrel_{other.is_pcrel_},
  size_{other.size_},
  type_{other.type_},
  architecture_{other.architecture_},
  is_scattered_{other.is_scattered_},
  value_{other.value_},
  section_{nullptr}
{}

void Relocation::swap(Relocation& other) {
  std::swap(this->address_,      other.address_);
  std::swap(this->symbol_,       other.symbol_);
  std::swap(this->is_pcrel_,     other.is_pcrel_);
  std::swap(this->size_,         other.size_);
  std::swap(this->type_,         other.type_);
  std::swap(this->architecture_, other.architecture_);
  std::swap(this->is_scattered_, other.is_scattered_);
  std::swap(this->value_,        other.value_);
  std::swap(this->section_,      other.section_);
}

uint32_t Relocation::address(void) const {
  return this->address_;
}
bool Relocation::is_pc_relative(void) const {
  return this->is_pcrel_;
}
uint8_t Relocation::size(void) const {
  return this->size_;
}
uint8_t Relocation::type(void) const {
  return this->type_;
}
bool Relocation::is_scattered(void) const {
  return this->is_scattered_;
}

int32_t Relocation::value(void) const {
  if (not this->is_scattered()) {
    throw not_found("This relocation is not a 'scattered' one");
  }
  return this->value_;
}

CPU_TYPES Relocation::architecture(void) const {
  return this->architecture_;
}

bool Relocation::has_symbol(void) const {
  return (this->symbol_ != nullptr);
}

Symbol& Relocation::symbol(void) {
  return const_cast<Symbol&>(static_cast<const Relocation*>(this)->symbol());
}

const Symbol& Relocation::symbol(void) const {
  if (not this->has_symbol()) {
    throw not_found("No symbol associated with this relocation");
  }
  return *this->symbol_;
}


bool Relocation::has_section(void) const {
  return (this->section_ != nullptr);
}

Section& Relocation::section(void) {
  return const_cast<Section&>(static_cast<const Relocation*>(this)->section());
}

const Section& Relocation::section(void) const {
  if (not this->has_section()) {
    throw not_found("No section associated with this relocation");
  }
  return *this->section_;
}


void Relocation::address(uint32_t address) {
  this->address_ = address;
}

void Relocation::pc_relative(bool val) {
  this->is_pcrel_ = val;
}

void Relocation::size(uint8_t size) {
  this->size_ = size;
}

void Relocation::type(uint8_t type) {
  this->type_ = type;
}

void Relocation::value(int32_t value) {
  if (not this->is_scattered()) {
    throw not_found("This relocation is not a 'scattered' one");
  }
  this->value_ = value;
}

void Relocation::accept(Visitor& visitor) const {
  visitor.visit(this->address());
  visitor.visit(this->is_pc_relative());
  visitor.visit(this->size());
  visitor.visit(this->type());
  visitor.visit(this->is_scattered());
  if (this->is_scattered()) {
    visitor.visit(this->value());
  }

  if (this->has_symbol()) {
    visitor(this->symbol());
  }

  if (this->has_section()) {
    visitor(this->section());
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


std::ostream& operator<<(std::ostream& os, const Relocation& relocation) {
  os << std::hex;
  os << std::left;

  std::string symbol_name = "";
  if (relocation.has_symbol()) {
    symbol_name = relocation.symbol().name();
  }

  std::string section_name = "";
  if (relocation.has_section()) {
    section_name = relocation.section().name();
  }

  std::string relocation_type = "";
  switch (relocation.architecture()) {
    case CPU_TYPES::CPU_TYPE_X86:
      {
        relocation_type = to_string(static_cast<X86_RELOCATION>(relocation.type()));
        break;
      }

    case CPU_TYPES::CPU_TYPE_X86_64:
      {
        relocation_type = to_string(static_cast<X86_64_RELOCATION>(relocation.type()));
        break;
      }

    case CPU_TYPES::CPU_TYPE_ARM:
      {
        relocation_type = to_string(static_cast<ARM_RELOCATION>(relocation.type()));
        break;
      }

    case CPU_TYPES::CPU_TYPE_ARM64:
      {
        relocation_type = to_string(static_cast<ARM64_RELOCATION>(relocation.type()));
        break;
      }

    case CPU_TYPES::CPU_TYPE_POWERPC:
      {
        relocation_type = to_string(static_cast<PPC_RELOCATION>(relocation.type()));
        break;
      }

    default:
      {
        relocation_type = std::to_string(relocation.type());
      }
  }


  os << std::setw(4) << relocation.address()
     << std::setw(20) << relocation_type
     << std::setw(4) << std::dec << static_cast<uint32_t>(relocation.size())
     << std::setw(6) << std::boolalpha << relocation.is_pc_relative()
     << std::setw(6) << std::boolalpha << relocation.is_scattered()
     << std::setw(10) << symbol_name
     << std::setw(10) << section_name;


  return os;
}


}
}
