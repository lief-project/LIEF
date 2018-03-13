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
#include "LIEF/MachO/RelocationDyld.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

RelocationDyld::~RelocationDyld(void) = default;

RelocationDyld::RelocationDyld(void) = default;
RelocationDyld& RelocationDyld::operator=(const RelocationDyld&) = default;
RelocationDyld::RelocationDyld(const RelocationDyld&) = default;

bool RelocationDyld::is_pc_relative(void) const {
  return static_cast<REBASE_TYPES>(this->type()) == REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32;
}


Relocation* RelocationDyld::clone(void) const {
  return new RelocationDyld(*this);
}


RELOCATION_ORIGINS RelocationDyld::origin(void) const {
  return RELOCATION_ORIGINS::ORIGIN_DYLDINFO;
}

void RelocationDyld::pc_relative(bool val) {
  if (this->is_pc_relative() == val) {
    return;
  }

  if (val == true) {
    this->type_ = static_cast<uint32_t>(REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32);
  }

  if (val == false) {
    if (this->size() == 32) {
      this->type_ = static_cast<uint32_t>(REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32);
    } else {
      this->type_ = static_cast<uint32_t>(REBASE_TYPES::REBASE_TYPE_POINTER);
    }
  }
}

void RelocationDyld::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool RelocationDyld::operator==(const RelocationDyld& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RelocationDyld::operator!=(const RelocationDyld& rhs) const {
  return not (*this == rhs);
}


std::ostream& RelocationDyld::print(std::ostream& os) const {
  return Relocation::print(os);
}


}
}
