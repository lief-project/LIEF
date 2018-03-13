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
#include "LIEF/PE/ExportEntry.hpp"

namespace LIEF {
namespace PE {
ExportEntry::~ExportEntry(void) = default;
ExportEntry::ExportEntry(const ExportEntry&) = default;
ExportEntry& ExportEntry::operator=(const ExportEntry&) = default;

ExportEntry::ExportEntry(void) :
  name_{""},
  ordinal_{0},
  address_{0},
  is_extern_{false}
{}


const std::string& ExportEntry::name(void) const {
  return this->name_;
}

uint16_t ExportEntry::ordinal(void) const {
  return this->ordinal_;
}

uint32_t ExportEntry::address(void) const {
  return this->address_;
}

bool ExportEntry::is_extern(void) const {
  return this->is_extern_;
}

void ExportEntry::name(const std::string& name) {
  this->name_ = name;
}

void ExportEntry::ordinal(uint16_t ordinal) {
  this->ordinal_ = ordinal;
}

void ExportEntry::address(uint32_t address) {
  this->address_ = address;
}

void ExportEntry::is_extern(bool is_extern) {
  this->is_extern_ = is_extern;
}

void ExportEntry::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool ExportEntry::operator==(const ExportEntry& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ExportEntry::operator!=(const ExportEntry& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ExportEntry& export_entry) {
  os << std::hex;
  os << std::left;
  std::string name = export_entry.name();
  if (name.size() > 20) {
    name = name.substr(0, 17) + "...";
  }
  os << std::setw(23) << name;
  os << std::setw(5)  << export_entry.ordinal();

  if (not export_entry.is_extern()) {
    os << std::setw(10) << export_entry.address();
  } else {
    os << std::setw(10) << "[Extern]";
  }
  return os;
}

}
}
