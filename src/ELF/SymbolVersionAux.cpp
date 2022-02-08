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
#include <utility>

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersionAux.hpp"

namespace LIEF {
namespace ELF {

SymbolVersionAux::~SymbolVersionAux() = default;
SymbolVersionAux& SymbolVersionAux::operator=(const SymbolVersionAux&) = default;
SymbolVersionAux::SymbolVersionAux(const SymbolVersionAux&) = default;

SymbolVersionAux::SymbolVersionAux() = default;

SymbolVersionAux::SymbolVersionAux(std::string  name) :
  name_{std::move(name)}
{}

const std::string& SymbolVersionAux::name() const {
  return name_;
}

void SymbolVersionAux::name(const std::string& name) {
  name_ = name;
}

void SymbolVersionAux::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersionAux::operator==(const SymbolVersionAux& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersionAux::operator!=(const SymbolVersionAux& rhs) const {
  return !(*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const SymbolVersionAux& symAux) {
  os << symAux.name();
  return os;
}
}
}
