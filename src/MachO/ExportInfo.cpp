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
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

ExportInfo::~ExportInfo(void) = default;

ExportInfo::ExportInfo(void) :
  node_offset_{0},
  flags_{0},
  address_{0},
  symbol_{nullptr}
{}


ExportInfo::ExportInfo(uint64_t address, uint64_t flags, uint64_t offset) :
  node_offset_{offset},
  flags_{flags},
  address_{address},
  symbol_{nullptr}
{}

ExportInfo& ExportInfo::operator=(ExportInfo other) {
  this->swap(other);
  return *this;
}

ExportInfo::ExportInfo(const ExportInfo& other) :
  Object{other},
  node_offset_{other.node_offset_},
  flags_{other.flags_},
  address_{other.address_},
  symbol_{nullptr}
{}

void ExportInfo::swap(ExportInfo& other) {
  std::swap(this->node_offset_, other.node_offset_);
  std::swap(this->flags_,       other.flags_);
  std::swap(this->address_,     other.address_);
  std::swap(this->symbol_,      other.symbol_);
}


uint64_t ExportInfo::node_offset(void) const {
  return this->node_offset_;
}

uint64_t ExportInfo::flags(void) const {
  return this->flags_;
}

void ExportInfo::flags(uint64_t flags) {
  this->flags_ = flags;
}

uint64_t ExportInfo::address(void) const {
  return this->address_;
}

void ExportInfo::address(uint64_t addr) {
  this->address_ = addr;
}

bool ExportInfo::has_symbol(void) const {
  return this->symbol_ != nullptr;
}

const Symbol& ExportInfo::symbol(void) const {
  if (not this->has_symbol()) {
    throw not_found("No symbol associated with this export info");
  }

  return *this->symbol_;
}

Symbol& ExportInfo::symbol(void) {
  return const_cast<Symbol&>(static_cast<const ExportInfo*>(this)->symbol());
}

void ExportInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ExportInfo::operator==(const ExportInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ExportInfo::operator!=(const ExportInfo& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ExportInfo& export_info) {

  os << std::hex;
  os << std::left;

  os << std::setw(13) << "Node Offset: " << std::hex << export_info.node_offset() << std::endl;
  os << std::setw(13) << "Flags: "       << std::hex << export_info.flags()       << std::endl;
  os << std::setw(13) << "Address: "     << std::hex << export_info.address()     << std::endl;
  if (export_info.has_symbol()) {
    os << std::setw(13) << "Symbol: "    << export_info.symbol().name() << std::endl;
  }

  return os;
}


}
}
