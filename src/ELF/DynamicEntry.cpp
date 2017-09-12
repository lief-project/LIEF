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
#include <stdexcept>
#include <iomanip>

#include "LIEF/exception.hpp"
#include "LIEF/visitors/Hash.hpp"

#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/EnumToString.hpp"

namespace LIEF {
namespace ELF {

DynamicEntry::DynamicEntry(void) = default;

DynamicEntry& DynamicEntry::operator=(const DynamicEntry&) = default;

DynamicEntry::DynamicEntry(const DynamicEntry&) = default;

DynamicEntry::~DynamicEntry(void) = default;

DynamicEntry::DynamicEntry(const Elf64_Dyn* header) :
  tag_{static_cast<DYNAMIC_TAGS>(header->d_tag)},
  value_{header->d_un.d_val}
{}


DynamicEntry::DynamicEntry(const Elf32_Dyn* header) :
  tag_{static_cast<DYNAMIC_TAGS>(header->d_tag)},
  value_{header->d_un.d_val}
{}


DynamicEntry::DynamicEntry(DYNAMIC_TAGS tag, uint64_t value) :
  tag_{tag},
  value_{value}
{}


DYNAMIC_TAGS DynamicEntry::tag(void) const {
  return this->tag_;
}


uint64_t DynamicEntry::value(void) const {
  return this->value_;
}

void DynamicEntry::tag(DYNAMIC_TAGS tag) {
  this->tag_ = tag;
}


void DynamicEntry::value(uint64_t value) {
  this->value_ = value;
}


const std::string& DynamicEntry::name(void) const {
  throw LIEF::not_found("This dynamic hasn't name field");
}


void DynamicEntry::name(const std::string&) {
  throw LIEF::not_found("This dynamic hasn't name field");
}


std::vector<uint64_t>& DynamicEntry::array(void) {
  throw LIEF::not_found("This dynamic entry hasn't array");
}


void DynamicEntry::array(const std::vector<uint64_t>&) {
  throw LIEF::not_found("This dynamic entry hasn't array");
}

void DynamicEntry::accept(Visitor& visitor) const {
  visitor(*this); // Double dispatch to avoid down-casting
  visitor.visit(this->value());
  visitor.visit(this->tag());
}


bool DynamicEntry::operator==(const DynamicEntry& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DynamicEntry::operator!=(const DynamicEntry& rhs) const {
  return not (*this == rhs);
}



std::ostream& DynamicEntry::print(std::ostream& os) const {
  os << std::hex;
  os << std::left
     << std::setw(20) << to_string(this->tag())
     << std::setw(10) << this->value();
  return os;
}


std::ostream& operator<<(std::ostream& os, const DynamicEntry& entry) {
  return entry.print(os);
}
}
}
