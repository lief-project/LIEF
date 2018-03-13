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

#include "LIEF/PE/Export.hpp"

namespace LIEF {
namespace PE {

Export::~Export(void) = default;
Export::Export(const Export&) = default;
Export& Export::operator=(const Export&) = default;

Export::Export(void) :
  exportFlags_{0},
  timestamp_{0},
  majorVersion_{0},
  minorVersion_{0},
  ordinalBase_{0}
{}

Export::Export(const pe_export_directory_table *header) :
  exportFlags_{header->ExportFlags},
  timestamp_{header->Timestamp},
  majorVersion_{header->MajorVersion},
  minorVersion_{header->MinorVersion},
  ordinalBase_{header->OrdinalBase}
{}

uint32_t Export::export_flags(void) const {
  return this->exportFlags_;
}

uint32_t Export::timestamp(void) const {
  return this->timestamp_;
}

uint16_t Export::major_version(void) const {
  return this->majorVersion_;
}

uint16_t Export::minor_version(void) const {
  return this->minorVersion_;
}

uint32_t Export::ordinal_base(void) const {
  return this->ordinalBase_;
}

const std::string& Export::name(void) const {
  return this->name_;
}

it_export_entries Export::entries(void) {
  return this->entries_;
}

it_const_export_entries Export::entries(void) const {
  return this->entries_;
}

void Export::export_flags(uint32_t flags) {
  this->exportFlags_ = flags;
}

void Export::timestamp(uint32_t timestamp) {
  this->timestamp_ = timestamp;
}

void Export::major_version(uint16_t major_version) {
  this->majorVersion_ = major_version;
}

void Export::minor_version(uint16_t minor_version) {
  this->minorVersion_ = minor_version;
}

void Export::ordinal_base(uint32_t ordinal_base) {
  this->ordinalBase_ = ordinal_base;
}

void Export::name(const std::string& name) {
  this->name_ = name;
}

void Export::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Export::operator==(const Export& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Export::operator!=(const Export& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Export& exp) {

  os << std::hex;
  os << std::left;
  os << exp.name() << std::endl;
  for (const ExportEntry& entry : exp.entries()) {
    os << "  " << entry << std::endl;
  }
  return os;
}

}
}
