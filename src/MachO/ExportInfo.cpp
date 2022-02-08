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

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/DylibCommand.hpp"

namespace LIEF {
namespace MachO {

ExportInfo::~ExportInfo() = default;

ExportInfo::ExportInfo() = default;

ExportInfo::ExportInfo(uint64_t address, uint64_t flags, uint64_t offset) :
  node_offset_{offset},
  flags_{flags},
  address_{address}
{}

ExportInfo& ExportInfo::operator=(ExportInfo other) {
  swap(other);
  return *this;
}

ExportInfo::ExportInfo(const ExportInfo& other) :
  Object{other},
  node_offset_{other.node_offset_},
  flags_{other.flags_},
  address_{other.address_},
  other_{other.other_}
{}

void ExportInfo::swap(ExportInfo& other) {
  std::swap(node_offset_,    other.node_offset_);
  std::swap(flags_,          other.flags_);
  std::swap(address_,        other.address_);
  std::swap(other_,          other.other_);
  std::swap(symbol_,         other.symbol_);
  std::swap(alias_,          other.alias_);
  std::swap(alias_location_, other.alias_location_);
}


bool ExportInfo::has(EXPORT_SYMBOL_FLAGS flag) const {
  return (flags_ & static_cast<uint64_t>(flag)) != 0u;
}

EXPORT_SYMBOL_KINDS ExportInfo::kind() const {
  static constexpr size_t EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03u;
  return static_cast<EXPORT_SYMBOL_KINDS>(flags_ & EXPORT_SYMBOL_FLAGS_KIND_MASK);
}


uint64_t ExportInfo::node_offset() const {
  return node_offset_;
}

uint64_t ExportInfo::flags() const {
  return flags_;
}

void ExportInfo::flags(uint64_t flags) {
  flags_ = flags;
}

uint64_t ExportInfo::address() const {
  return address_;
}

uint64_t ExportInfo::other() const {
  return other_;
}

Symbol* ExportInfo::alias() {
  return alias_;
}

const Symbol* ExportInfo::alias() const {
  return alias_;
}

DylibCommand* ExportInfo::alias_library() {
  return alias_location_;
}

const DylibCommand* ExportInfo::alias_library() const {
  return alias_location_;
}

void ExportInfo::address(uint64_t addr) {
  address_ = addr;
}

bool ExportInfo::has_symbol() const {
  return symbol_ != nullptr;
}

const Symbol* ExportInfo::symbol() const {
  return symbol_;
}

Symbol* ExportInfo::symbol() {
  return const_cast<Symbol*>(static_cast<const ExportInfo*>(this)->symbol());
}


ExportInfo::flag_list_t ExportInfo::flags_list() const {
  flag_list_t flags;

  std::copy_if(std::begin(export_symbol_flags), std::end(export_symbol_flags),
               std::back_inserter(flags),
               [this] (EXPORT_SYMBOL_FLAGS f) { return has(f); });

  return flags;
}

void ExportInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool ExportInfo::operator==(const ExportInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ExportInfo::operator!=(const ExportInfo& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ExportInfo& export_info) {

  const ExportInfo::flag_list_t& flags = export_info.flags_list();

  std::string flags_str = std::accumulate(
      std::begin(flags),
      std::end(flags), std::string{},
     [] (const std::string& a, EXPORT_SYMBOL_FLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });

  os << std::hex;
  os << std::left;

  os << std::setw(13) << "Node Offset: " << std::hex << export_info.node_offset()     << std::endl;
  os << std::setw(13) << "Flags: "       << std::hex << export_info.flags()           << std::endl;
  os << std::setw(13) << "Address: "     << std::hex << export_info.address()         << std::endl;
  os << std::setw(13) << "Kind: "        << to_string(export_info.kind()) << std::endl;
  os << std::setw(13) << "Flags: "       << flags_str << std::endl;
  if (export_info.has_symbol()) {
    os << std::setw(13) << "Symbol: "    << export_info.symbol()->name() << std::endl;
  }

  if (export_info.alias() != nullptr) {
    os << std::setw(13) << "Alias Symbol: " << export_info.alias()->name();
    if (export_info.alias_library() != nullptr) {
      os << " from " << export_info.alias_library()->name();
    }
    os << std::endl;
  }

  return os;
}


}
}
