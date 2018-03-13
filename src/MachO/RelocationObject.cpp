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

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/RelocationObject.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/Section.hpp"

namespace LIEF {
namespace MachO {


RelocationObject& RelocationObject::operator=(RelocationObject other) {
  this->swap(other);
  return *this;
}

RelocationObject::RelocationObject(const RelocationObject& other) :
  Relocation{other},
  is_pcrel_{other.is_pcrel_},
  is_scattered_{other.is_scattered_},
  value_{other.value_}
{}

RelocationObject::~RelocationObject(void) = default;

RelocationObject::RelocationObject(void) :
  Relocation::Relocation{},
  is_pcrel_{false},
  is_scattered_{false},
  value_{0}
{}

RelocationObject::RelocationObject(const relocation_info *relocinfo) :
  Relocation::Relocation{},
  is_pcrel_{static_cast<bool>(relocinfo->r_pcrel)},
  is_scattered_{false},
  value_{0}
{
  this->address_ = static_cast<uint32_t>(relocinfo->r_address);
  this->size_    = static_cast<uint8_t>(relocinfo->r_length);
  this->type_    = static_cast<uint8_t>(relocinfo->r_type);
}

RelocationObject::RelocationObject(const scattered_relocation_info *scattered_relocinfo) :
  Relocation::Relocation{},
  is_pcrel_{static_cast<bool>(scattered_relocinfo->r_pcrel)},
  is_scattered_{true},
  value_{scattered_relocinfo->r_value}
{
  this->address_ = scattered_relocinfo->r_address;
  this->size_    = static_cast<uint8_t>(scattered_relocinfo->r_length);
  this->type_    = static_cast<uint8_t>(scattered_relocinfo->r_type);
}


RelocationObject* RelocationObject::clone(void) const {
  return new RelocationObject(*this);
}


void RelocationObject::swap(RelocationObject& other) {
  Relocation::swap(other);

  std::swap(this->is_pcrel_,     other.is_pcrel_);
  std::swap(this->is_scattered_, other.is_scattered_);
  std::swap(this->value_,        other.value_);
}

bool RelocationObject::is_pc_relative(void) const {
  return this->is_pcrel_;
}

size_t RelocationObject::size(void) const {
  if (this->size_ < 2) {
    return (this->size_ + 1) * 8;
  } else {
    return sizeof(uint32_t) * 8;
  }
}


bool RelocationObject::is_scattered(void) const {
  return this->is_scattered_;
}


uint64_t RelocationObject::address(void) const {
  if (not this->has_section()) {
    return Relocation::address();
  }

  return this->address_ + this->section().offset();
}

int32_t RelocationObject::value(void) const {
  if (not this->is_scattered()) {
    throw not_found("This relocation is not a 'scattered' one");
  }
  return this->value_;
}

RELOCATION_ORIGINS RelocationObject::origin(void) const {
  return RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE;
}


void RelocationObject::pc_relative(bool val) {
  this->is_pcrel_ = val;
}

void RelocationObject::size(size_t size) {
  switch(size) {
    case 8:
      {
        this->size_ = 0;
        break;
      }

    case 16:
      {
        this->size_ = 1;
        break;
      }

    case 32:
      {
        this->size_ = 2;
        break;
      }

    default:
      {
        throw integrity_error("Size must not be bigger than 32 bits");
      }
  }
}

void RelocationObject::value(int32_t value) {
  if (not this->is_scattered()) {
    throw not_found("This relocation is not a 'scattered' one");
  }
  this->value_ = value;
}


void RelocationObject::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool RelocationObject::operator==(const RelocationObject& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RelocationObject::operator!=(const RelocationObject& rhs) const {
  return not (*this == rhs);
}


std::ostream& RelocationObject::print(std::ostream& os) const {
  return Relocation::print(os);
}


}
}
