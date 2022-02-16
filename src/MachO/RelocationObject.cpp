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
#include <numeric>
#include <iomanip>
#include "logging.hpp"

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/RelocationObject.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/Section.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {
RelocationObject::RelocationObject(const RelocationObject& other) = default;
RelocationObject::~RelocationObject() = default;
RelocationObject::RelocationObject() = default;

RelocationObject& RelocationObject::operator=(RelocationObject other) {
  swap(other);
  return *this;
}

RelocationObject::RelocationObject(const details::relocation_info& relocinfo) :
  is_pcrel_{static_cast<bool>(relocinfo.r_pcrel)}
{
  address_ = static_cast<uint32_t>(relocinfo.r_address);
  size_    = static_cast<uint8_t>(relocinfo.r_length);
  type_    = static_cast<uint8_t>(relocinfo.r_type);
}

RelocationObject::RelocationObject(const details::scattered_relocation_info& scattered_relocinfo) :
  is_pcrel_{static_cast<bool>(scattered_relocinfo.r_pcrel)},
  is_scattered_{true},
  value_{scattered_relocinfo.r_value}
{
  address_ = scattered_relocinfo.r_address;
  size_    = static_cast<uint8_t>(scattered_relocinfo.r_length);
  type_    = static_cast<uint8_t>(scattered_relocinfo.r_type);
}


RelocationObject* RelocationObject::clone() const {
  return new RelocationObject(*this);
}


void RelocationObject::swap(RelocationObject& other) {
  Relocation::swap(other);

  std::swap(is_pcrel_,     other.is_pcrel_);
  std::swap(is_scattered_, other.is_scattered_);
  std::swap(value_,        other.value_);
}

bool RelocationObject::is_pc_relative() const {
  return is_pcrel_;
}

size_t RelocationObject::size() const {
  if (size_ < 2) {
    return (size_ + 1) * 8;
  }
  return sizeof(uint32_t) * 8;
}


bool RelocationObject::is_scattered() const {
  return is_scattered_;
}


uint64_t RelocationObject::address() const {
  const Section* sec = section();
  if (sec == nullptr) {
    return Relocation::address();
  }

  return address_ + section()->offset();
}

int32_t RelocationObject::value() const {
  if (!is_scattered()) {
    LIEF_ERR("This relocation is not a 'scattered' one");
    return -1;
  }
  return value_;
}

RELOCATION_ORIGINS RelocationObject::origin() const {
  return RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE;
}


void RelocationObject::pc_relative(bool val) {
  is_pcrel_ = val;
}

void RelocationObject::size(size_t size) {
  switch(size) {
    case 8:  size_ = 0; break;
    case 16: size_ = 1; break;
    case 32: size_ = 2; break;
    default: LIEF_ERR("Size must not be bigger than 32 bits");
  }
}

void RelocationObject::value(int32_t value) {
  if (!is_scattered()) {
    LIEF_ERR("This relocation is not a 'scattered' one");
    return;
  }
  value_ = value;
}


void RelocationObject::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool RelocationObject::operator==(const RelocationObject& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RelocationObject::operator!=(const RelocationObject& rhs) const {
  return !(*this == rhs);
}


bool RelocationObject::classof(const Relocation& r) {
  return r.origin() == RELOCATION_ORIGINS::ORIGIN_RELOC_TABLE;
}

std::ostream& RelocationObject::print(std::ostream& os) const {
  return Relocation::print(os);
}


}
}
