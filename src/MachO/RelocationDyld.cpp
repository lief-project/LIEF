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
#include "LIEF/MachO/RelocationDyld.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

RelocationDyld::~RelocationDyld() = default;

RelocationDyld::RelocationDyld() = default;
RelocationDyld& RelocationDyld::operator=(const RelocationDyld&) = default;
RelocationDyld::RelocationDyld(const RelocationDyld&) = default;

bool RelocationDyld::is_pc_relative() const {
  return static_cast<REBASE_TYPES>(type()) == REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32;
}


Relocation* RelocationDyld::clone() const {
  return new RelocationDyld(*this);
}


RELOCATION_ORIGINS RelocationDyld::origin() const {
  return RELOCATION_ORIGINS::ORIGIN_DYLDINFO;
}

void RelocationDyld::pc_relative(bool val) {
  if (is_pc_relative() == val) {
    return;
  }

  if (val) {
    type_ = static_cast<uint32_t>(REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32);
  } else {
    if (size() == 32) {
      type_ = static_cast<uint32_t>(REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32);
    } else {
      type_ = static_cast<uint32_t>(REBASE_TYPES::REBASE_TYPE_POINTER);
    }
  }
}

void RelocationDyld::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool RelocationDyld::operator==(const RelocationDyld& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool RelocationDyld::operator!=(const RelocationDyld& rhs) const {
  return !(*this == rhs);
}

bool RelocationDyld::operator<(const RelocationDyld& rhs) const {
  // From ld/OutputFile.h
  if (type() != rhs.type()) {
    return type() < rhs.type();
  }
  return address() < rhs.address();
}

bool RelocationDyld::operator>=(const RelocationDyld& rhs) const {
  return !(*this < rhs);
}

bool RelocationDyld::operator>(const RelocationDyld& rhs) const {
  if (type() != rhs.type()) {
    return type() > rhs.type();
  }
  return address() > rhs.address();
}

bool RelocationDyld::operator<=(const RelocationDyld& rhs) const {
  return !(*this > rhs);
}


bool RelocationDyld::classof(const Relocation& r) {
  return r.origin() == RELOCATION_ORIGINS::ORIGIN_DYLDINFO;
}


std::ostream& RelocationDyld::print(std::ostream& os) const {
  return Relocation::print(os);
}


}
}
