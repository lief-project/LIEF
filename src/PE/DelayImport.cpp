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
#include <algorithm>
#include <iomanip>
#include <utility>
#include "logging.hpp"

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/DelayImport.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

DelayImport::~DelayImport() = default;

DelayImport::DelayImport() = default;

DelayImport& DelayImport::operator=(const DelayImport&) = default;
DelayImport::DelayImport(const DelayImport&) = default;


DelayImport::DelayImport(DelayImport&&) = default;
DelayImport& DelayImport::operator=(DelayImport&&) = default;

void DelayImport::swap(DelayImport& other) {
  std::swap(attribute_,   other.attribute_);
  std::swap(name_,        other.name_);
  std::swap(handle_,      other.handle_);
  std::swap(iat_,         other.iat_);
  std::swap(names_table_, other.names_table_);
  std::swap(bound_iat_,   other.bound_iat_);
  std::swap(unload_iat_,  other.unload_iat_);
  std::swap(timestamp_,   other.timestamp_);
  std::swap(entries_,     other.entries_);
  std::swap(type_,        other.type_);
}


DelayImport::DelayImport(const details::delay_imports& import, PE_TYPE type) :
  attribute_{import.attribute},
  handle_{import.handle},
  iat_{import.iat},
  names_table_{import.name_table},
  bound_iat_{import.bound_iat},
  unload_iat_{import.unload_iat},
  timestamp_{import.timestamp},
  type_{type}
{}


DelayImport::DelayImport(std::string name) :
  name_{std::move(name)}
{}

const std::string& DelayImport::name() const {
  return name_;
}


void DelayImport::name(std::string name) {
  name_ = std::move(name);
}

DelayImport::it_entries DelayImport::entries() {
  return entries_;
}

DelayImport::it_const_entries DelayImport::entries() const {
  return entries_;
}


uint32_t DelayImport::attribute() const {
  return attribute_;
}

void DelayImport::attribute(uint32_t hdl) {
  attribute_ = hdl;
}

uint32_t DelayImport::handle() const {
  return handle_;
}

void DelayImport::handle(uint32_t hdl) {
  handle_ = hdl;
}


uint32_t DelayImport::iat() const {
  return iat_;
}

void DelayImport::iat(uint32_t iat) {
  iat_ = iat;
}

uint32_t DelayImport::names_table() const {
  return names_table_;
}

void DelayImport::names_table(uint32_t value) {
  names_table_ = value;
}

uint32_t DelayImport::biat() const {
  return bound_iat_;
}

void DelayImport::biat(uint32_t value) {
  bound_iat_ = value;
}

uint32_t DelayImport::uiat() const {
  return unload_iat_;
}

void DelayImport::uiat(uint32_t value) {
  unload_iat_ = value;
}

void DelayImport::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

uint32_t DelayImport::timestamp() const {
  return timestamp_;
}

void DelayImport::timestamp(uint32_t value) {
  timestamp_ = value;
}

bool DelayImport::operator==(const DelayImport& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DelayImport::operator!=(const DelayImport& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const DelayImport& entry) {
  os << fmt::format("{:<20}: #{} imports", entry.name(), entry.entries().size());
  return os;
}
}
}
