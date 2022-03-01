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
#include "spdlog/fmt/fmt.h"

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/DelayImportEntry.hpp"


namespace LIEF {
namespace PE {
DelayImportEntry::DelayImportEntry(const DelayImportEntry&) = default;
DelayImportEntry& DelayImportEntry::operator=(const DelayImportEntry&) = default;

DelayImportEntry::DelayImportEntry(DelayImportEntry&&) = default;
DelayImportEntry& DelayImportEntry::operator=(DelayImportEntry&&) = default;

DelayImportEntry::~DelayImportEntry() = default;

DelayImportEntry::DelayImportEntry() = default;


DelayImportEntry::DelayImportEntry(uint64_t data, PE_TYPE type) :
  data_{data},
  type_{type}
{}

bool DelayImportEntry::is_ordinal() const {
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

uint16_t DelayImportEntry::ordinal() const {
  return data_ & 0xFFFF;
}

uint16_t DelayImportEntry::hint() const {
  return hint_;
}

uint64_t DelayImportEntry::iat_value() const {
  return iat_value_;
}

uint64_t DelayImportEntry::hint_name_rva() const {
  return data();
}

uint64_t DelayImportEntry::data() const {
  return data_;
}

void DelayImportEntry::data(uint64_t data) {
  data_ = data;
}


void DelayImportEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool DelayImportEntry::operator==(const DelayImportEntry& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DelayImportEntry::operator!=(const DelayImportEntry& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const DelayImportEntry& entry) {
  if (entry.is_ordinal()) {
    os << "#" << entry.ordinal();
  } else {
    os << fmt::format("{:<20}", entry.name());
  }

  os << fmt::format(": 0x{:x}", entry.iat_value());
  return os;
}

} // namespace PE
} // namepsace LIEF
