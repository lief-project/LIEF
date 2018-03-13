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

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/ImportEntry.hpp"


namespace LIEF {
namespace PE {
ImportEntry::ImportEntry(const ImportEntry&) = default;
ImportEntry& ImportEntry::operator=(const ImportEntry&) = default;
ImportEntry::~ImportEntry(void) = default;

ImportEntry::ImportEntry(void) :
  data_{0},
  name_{""},
  hint_{0},
  iat_value_{0},
  rva_{0},
  type_{PE_TYPE::PE32}
{}

ImportEntry::ImportEntry(uint64_t data, const std::string& name) :
  data_{data},
  name_{name},
  hint_{0},
  iat_value_{0},
  rva_{0},
  type_{PE_TYPE::PE32}
{}


ImportEntry::ImportEntry(const std::string& name) :
  ImportEntry{0, name}
{}

bool ImportEntry::is_ordinal(void) const {
  if (this->type_ == PE_TYPE::PE32) {
    return this->data_ & 0x80000000;
  } else {
    return this->data_ & 0x8000000000000000;
  }
}

uint16_t ImportEntry::ordinal(void) const {
  if (not this->is_ordinal()) {
    throw LIEF::not_found("This import is not ordinal");
  }

  return this->data_ & 0xFFFF;
}

uint16_t ImportEntry::hint(void) const {
  return this->hint_;
}

uint64_t ImportEntry::iat_value(void) const {
  return this->iat_value_;
}


uint64_t ImportEntry::hint_name_rva(void) const {
  return this->data();
}

const std::string& ImportEntry::name(void) const {
  return this->name_;
}

uint64_t ImportEntry::data(void) const {
  return this->data_;
}

uint64_t ImportEntry::iat_address(void) const {
  return this->rva_;
}

void ImportEntry::name(const std::string& name) {
  this->name_ = name;
}

void ImportEntry::data(uint64_t data) {
  this->data_ = data;
}


void ImportEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool ImportEntry::operator==(const ImportEntry& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ImportEntry::operator!=(const ImportEntry& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ImportEntry& entry) {
  os << std::hex;
  os << std::left;
  if (not entry.is_ordinal()) {
    os << std::setw(33) << entry.name();
  }
  os << std::setw(20) << entry.data();
  os << std::setw(20) << entry.iat_value();
  os << std::setw(20) << entry.hint();
  return os;
}

} // namespace PE
} // namepsace LIEF
