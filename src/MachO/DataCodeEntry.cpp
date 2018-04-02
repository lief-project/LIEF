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

#include "LIEF/MachO/DataCodeEntry.hpp"

namespace LIEF {
namespace MachO {

DataCodeEntry& DataCodeEntry::operator=(const DataCodeEntry&) = default;
DataCodeEntry::DataCodeEntry(const DataCodeEntry&) = default;
DataCodeEntry::~DataCodeEntry(void) = default;

DataCodeEntry::DataCodeEntry(void) :
  offset_{0},
  length_{0},
  type_{TYPES::UNKNOWN}
{}

DataCodeEntry::DataCodeEntry(uint32_t off, uint16_t length, TYPES type) :
  offset_{off},
  length_{length},
  type_{type}
{}

DataCodeEntry::DataCodeEntry(const data_in_code_entry* entry) :
  offset_{entry->offset},
  length_{entry->length},
  type_{static_cast<TYPES>(entry->kind)}
{}


uint32_t DataCodeEntry::offset(void) const {
  return this->offset_;
}

uint16_t DataCodeEntry::length(void) const {
  return this->length_;
}

DataCodeEntry::TYPES DataCodeEntry::type(void) const {
  return this->type_;
}

void DataCodeEntry::offset(uint32_t off) {
  this->offset_ = off;
}

void DataCodeEntry::length(uint16_t length) {
  this->length_ = length;
}

void DataCodeEntry::type(TYPES type) {
  this->type_ = type;
}

void DataCodeEntry::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DataCodeEntry::operator==(const DataCodeEntry& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DataCodeEntry::operator!=(const DataCodeEntry& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const DataCodeEntry& entry) {
  return os;
}




}
}
