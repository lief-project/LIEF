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
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/DyldBindingInfo.hpp"
#include "LIEF/MachO/Symbol.hpp"

namespace LIEF {
namespace MachO {

DyldBindingInfo::~DyldBindingInfo() = default;
DyldBindingInfo::DyldBindingInfo() = default;

DyldBindingInfo& DyldBindingInfo::operator=(DyldBindingInfo&&) = default;
DyldBindingInfo::DyldBindingInfo(DyldBindingInfo&&) = default;
DyldBindingInfo::DyldBindingInfo(const DyldBindingInfo& other) = default;

DyldBindingInfo::DyldBindingInfo(BINDING_CLASS cls, BIND_TYPES type, uint64_t address,
                                 int64_t addend, int32_t oridnal, bool is_weak, bool is_non_weak_definition,
                                 uint64_t offset) :
  class_{cls},
  binding_type_{type},
  is_non_weak_definition_{is_non_weak_definition},
  offset_{offset}
{
  library_ordinal_ = oridnal;
  addend_          = addend;
  is_weak_import_  = is_weak;
  address_         = address;
}


DyldBindingInfo& DyldBindingInfo::operator=(DyldBindingInfo other) {
  swap(other);
  return *this;
}



void DyldBindingInfo::swap(DyldBindingInfo& other) {
  BindingInfo::swap(other);
  std::swap(class_,                   other.class_);
  std::swap(binding_type_,            other.binding_type_);
  std::swap(is_non_weak_definition_,  other.is_non_weak_definition_);
  std::swap(offset_,                  other.offset_);
}

BINDING_CLASS DyldBindingInfo::binding_class() const {
  return class_;
}

void DyldBindingInfo::binding_class(BINDING_CLASS bind_class) {
  class_ = bind_class;
}

BIND_TYPES DyldBindingInfo::binding_type() const {
  return binding_type_;
}

void DyldBindingInfo::binding_type(BIND_TYPES type) {
  binding_type_ = type;
}

uint64_t DyldBindingInfo::original_offset() const {
  return offset_;
}

void DyldBindingInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool DyldBindingInfo::operator==(const DyldBindingInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  if (&rhs == this) { return true; }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DyldBindingInfo::operator!=(const DyldBindingInfo& rhs) const {
  return !(*this == rhs);
}

bool DyldBindingInfo::classof(const BindingInfo& info) {
  return info.type() == BindingInfo::TYPES::DYLD_INFO;
}

std::ostream& operator<<(std::ostream& os, const DyldBindingInfo& info) {
  os << static_cast<const BindingInfo&>(info);
  return os;
}


}
}
