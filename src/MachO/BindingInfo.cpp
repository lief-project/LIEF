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
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

BindingInfo::~BindingInfo(void) = default;

BindingInfo::BindingInfo(void) :
  class_{BINDING_CLASS::BIND_CLASS_STANDARD},
  binding_type_{BIND_TYPES::BIND_TYPE_POINTER},
  segment_{nullptr},
  symbol_{nullptr},
  library_ordinal_{0},
  addend_{0},
  is_weak_import_{false},
  library_{nullptr},
  address_{0}
{}


BindingInfo::BindingInfo(BINDING_CLASS cls, BIND_TYPES type, uint64_t address, int64_t addend, int32_t oridnal, bool is_weak) :
  class_{cls},
  binding_type_{type},
  segment_{nullptr},
  symbol_{nullptr},
  library_ordinal_{oridnal},
  addend_{addend},
  is_weak_import_{is_weak},
  library_{nullptr},
  address_{address}
{}


BindingInfo& BindingInfo::operator=(BindingInfo other) {
  this->swap(other);
  return *this;
}

BindingInfo::BindingInfo(const BindingInfo& other) :
  Object{other},
  class_{other.class_},
  binding_type_{other.binding_type_},
  segment_{nullptr},
  symbol_{nullptr},
  library_ordinal_{other.library_ordinal_},
  addend_{other.addend_},
  is_weak_import_{other.is_weak_import_},
  library_{nullptr},
  address_{other.address_}
{}

void BindingInfo::swap(BindingInfo& other) {
  std::swap(this->class_,           other.class_);
  std::swap(this->binding_type_,    other.binding_type_);
  std::swap(this->segment_,         other.segment_);
  std::swap(this->symbol_,          other.symbol_);
  std::swap(this->library_ordinal_, other.library_ordinal_);
  std::swap(this->addend_,          other.addend_);
  std::swap(this->is_weak_import_,  other.is_weak_import_);
  std::swap(this->library_,         other.library_);
  std::swap(this->address_,         other.address_);
}


bool BindingInfo::has_segment(void) const {
  return this->segment_ != nullptr;
}

const SegmentCommand& BindingInfo::segment(void) const {
  if (not this->has_segment()) {
    throw not_found("No segment associated with this binding");
  }

  return *this->segment_;
}

SegmentCommand& BindingInfo::segment(void) {
  return const_cast<SegmentCommand&>(static_cast<const BindingInfo*>(this)->segment());
}

bool BindingInfo::has_symbol(void) const {
  return this->symbol_ != nullptr;
}

const Symbol& BindingInfo::symbol(void) const {
  if (not this->has_symbol()) {
    throw not_found("No symbol associated with this binding");
  }

  return *this->symbol_;
}

Symbol& BindingInfo::symbol(void) {
  return const_cast<Symbol&>(static_cast<const BindingInfo*>(this)->symbol());
}



bool BindingInfo::has_library(void) const {
  return this->library_ != nullptr;
}

const DylibCommand& BindingInfo::library(void) const {
  if (not this->has_library()) {
    throw not_found("No library associated with this binding");
  }

  return *this->library_;
}

DylibCommand& BindingInfo::library(void) {
  return const_cast<DylibCommand&>(static_cast<const BindingInfo*>(this)->library());
}

BINDING_CLASS BindingInfo::binding_class(void) const {
  return this->class_;
}

void BindingInfo::binding_class(BINDING_CLASS bind_class) {
  this->class_ = bind_class;
}

BIND_TYPES BindingInfo::binding_type(void) const {
  return this->binding_type_;
}

void BindingInfo::binding_type(BIND_TYPES type) {
  this->binding_type_ = type;
}

int32_t BindingInfo::library_ordinal(void) const {
  return this->library_ordinal_;
}

void BindingInfo::library_ordinal(int32_t ordinal) {
  this->library_ordinal_ = ordinal;
}

int64_t BindingInfo::addend(void) const {
  return this->addend_;
}

void BindingInfo::addend(int64_t addend) {
  this->addend_ = addend;
}

bool BindingInfo::is_weak_import(void) const {
  return this->is_weak_import_;
}

void BindingInfo::set_weak_import(bool val) {
  this->is_weak_import_ = val;
}


uint64_t BindingInfo::address(void) const {
  return this->address_;
}

void BindingInfo::address(uint64_t addr) {
  this->address_ = addr;
}

void BindingInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool BindingInfo::operator==(const BindingInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool BindingInfo::operator!=(const BindingInfo& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const BindingInfo& binding_info) {

  os << std::hex;
  os << std::left;

  os << std::setw(13) << "Class: " <<  to_string(binding_info.binding_class()) << std::endl;
  os << std::setw(13) << "Type: " <<  to_string(binding_info.binding_type()) << std::endl;
  os << std::setw(13) << "Address: 0x" <<  std::hex << binding_info.address() << std::endl;

  if (binding_info.has_symbol()) {
    os << std::setw(13) << "Symbol: "    << binding_info.symbol().name() << std::endl;
  }

  if (binding_info.has_symbol()) {
    os << std::setw(13) << "Segment: "    << binding_info.segment().name() << std::endl;
  }

  if (binding_info.has_library()) {
    os << std::setw(13) << "Library: "    << binding_info.library().name() << std::endl;
  }

  return os;
}


}
}
