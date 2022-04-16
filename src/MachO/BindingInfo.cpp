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
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/DylibCommand.hpp"

namespace LIEF {
namespace MachO {

BindingInfo::BindingInfo() = default;
BindingInfo::~BindingInfo() = default;

BindingInfo::BindingInfo(const BindingInfo& other) :
  Object{other},
  library_ordinal_{other.library_ordinal_},
  addend_{other.addend_},
  is_weak_import_{other.is_weak_import_},
  address_{other.address_}
{}

void BindingInfo::swap(BindingInfo& other) {
  std::swap(segment_,         other.segment_);
  std::swap(symbol_,          other.symbol_);
  std::swap(library_ordinal_, other.library_ordinal_);
  std::swap(addend_,          other.addend_);
  std::swap(is_weak_import_,  other.is_weak_import_);
  std::swap(library_,         other.library_);
  std::swap(address_,         other.address_);
}


bool BindingInfo::has_segment() const {
  return segment_ != nullptr;
}

const SegmentCommand* BindingInfo::segment() const {
  return segment_;
}

SegmentCommand* BindingInfo::segment() {
  return const_cast<SegmentCommand*>(static_cast<const BindingInfo*>(this)->segment());
}

bool BindingInfo::has_symbol() const {
  return symbol_ != nullptr;
}

const Symbol* BindingInfo::symbol() const {
  return symbol_;
}

Symbol* BindingInfo::symbol() {
  return const_cast<Symbol*>(static_cast<const BindingInfo*>(this)->symbol());
}

bool BindingInfo::has_library() const {
  return library_ != nullptr;
}

const DylibCommand* BindingInfo::library() const {
  return library_;
}

DylibCommand* BindingInfo::library() {
  return const_cast<DylibCommand*>(static_cast<const BindingInfo*>(this)->library());
}

int32_t BindingInfo::library_ordinal() const {
  return library_ordinal_;
}

void BindingInfo::library_ordinal(int32_t ordinal) {
  library_ordinal_ = ordinal;
}

int64_t BindingInfo::addend() const {
  return addend_;
}

void BindingInfo::addend(int64_t addend) {
  addend_ = addend;
}

bool BindingInfo::is_weak_import() const {
  return is_weak_import_;
}

void BindingInfo::set_weak_import(bool val) {
  is_weak_import_ = val;
}


uint64_t BindingInfo::address() const {
  return address_;
}

void BindingInfo::address(uint64_t addr) {
  address_ = addr;
}

void BindingInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool BindingInfo::operator==(const BindingInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  if (&rhs == this) { return true; }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool BindingInfo::operator!=(const BindingInfo& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const BindingInfo& binding_info) {

  os << std::hex;
  os << std::left;

  os << std::setw(13) << "Address: 0x" <<  std::hex << binding_info.address() << std::endl;

  if (binding_info.has_symbol()) {
    os << std::setw(13) << "Symbol: "    << binding_info.symbol()->name() << std::endl;
  }

  if (binding_info.has_segment()) {
    os << std::setw(13) << "Segment: "    << binding_info.segment()->name() << std::endl;
  }

  if (binding_info.has_library()) {
    os << std::setw(13) << "Library: "    << binding_info.library()->name() << std::endl;
  }

  return os;
}


}
}
