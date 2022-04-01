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

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/ImportEntry.hpp"
#include "logging.hpp"


namespace LIEF {
namespace PE {
ImportEntry::ImportEntry(const ImportEntry&) = default;
ImportEntry& ImportEntry::operator=(const ImportEntry&) = default;
ImportEntry::~ImportEntry() = default;

ImportEntry::ImportEntry() = default;

ImportEntry::ImportEntry(uint64_t data, const std::string& name) :
  data_{data},
  type_{PE_TYPE::PE32}
{
  name_ = name;
}


ImportEntry::ImportEntry(const std::string& name) :
  ImportEntry{0, name}
{}

bool ImportEntry::is_ordinal() const {
  // See: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-idata-section
  const uint64_t ORDINAL_MASK = type_ == PE_TYPE::PE32 ? 0x80000000 : 0x8000000000000000;
  bool ordinal_bit_is_set = static_cast<bool>(data_ & ORDINAL_MASK);

  // Check that bit 31 / 63 is set
  if (!ordinal_bit_is_set) {
    return false;
  }
  // Check that bits 30-15 / 62-15 are set to 0.
  uint64_t val = (data_ & ~ORDINAL_MASK) >> 15;
  return val == 0;
}

uint16_t ImportEntry::ordinal() const {
  if (!is_ordinal()) {
    LIEF_WARN("This import is not ordinal");
    return 0;
  }

  return data_ & 0xFFFF;
}

uint16_t ImportEntry::hint() const {
  return hint_;
}

uint64_t ImportEntry::iat_value() const {
  return iat_value_;
}


uint64_t ImportEntry::hint_name_rva() const {
  return data();
}

uint64_t ImportEntry::data() const {
  return data_;
}

uint64_t ImportEntry::iat_address() const {
  return rva_;
}

void ImportEntry::data(uint64_t data) {
  data_ = data;
}


void ImportEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool ImportEntry::operator==(const ImportEntry& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ImportEntry::operator!=(const ImportEntry& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ImportEntry& entry) {
  os << std::hex;
  os << std::left;
  if (!entry.is_ordinal()) {
    os << std::setw(33) << entry.name();
  }
  os << std::setw(20) << entry.data();
  os << std::setw(20) << entry.iat_value();
  os << std::setw(20) << entry.hint();
  return os;
}

} // namespace PE
} // namepsace LIEF
