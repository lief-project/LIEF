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
#include <iomanip>

#include "LIEF/exception.hpp"
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

namespace LIEF {
namespace ELF {

SymbolVersion::SymbolVersion() = default;
SymbolVersion::~SymbolVersion() = default;

SymbolVersion& SymbolVersion::operator=(const SymbolVersion&) = default;

SymbolVersion::SymbolVersion(const SymbolVersion&) = default;

SymbolVersion::SymbolVersion(uint16_t value) :
  value_{value}
{}


SymbolVersion SymbolVersion::local() {
  return SymbolVersion{0};
}

SymbolVersion SymbolVersion::global() {
  return SymbolVersion{1};
}

uint16_t SymbolVersion::value() const {
  return value_;
}


bool SymbolVersion::has_auxiliary_version() const {
  return symbol_aux_ != nullptr;
}

const SymbolVersionAux* SymbolVersion::symbol_version_auxiliary() const {
  return symbol_aux_;
}

SymbolVersionAux* SymbolVersion::symbol_version_auxiliary() {
  return const_cast<SymbolVersionAux*>(static_cast<const SymbolVersion*>(this)->symbol_version_auxiliary());
}

void SymbolVersion::symbol_version_auxiliary(SymbolVersionAuxRequirement& svauxr) {
  symbol_aux_ = &svauxr;
  value_      = svauxr.other();
}

void SymbolVersion::value(uint16_t value) {
  value_ = value;
}

void SymbolVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersion::operator==(const SymbolVersion& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersion::operator!=(const SymbolVersion& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ELF::SymbolVersion& symv) {
  if (symv.has_auxiliary_version()) {
    os << symv.symbol_version_auxiliary()->name() << "(" << symv.value() << ")";
  } else {
    std::string type;
    if (symv.value() == 0) {
      type = "* Local *";
    } else if (symv.value() == 1){
      type = "* Global *";
    } else {
      type = "* ERROR (" + std::to_string(symv.value()) + ") *";
    }
    os << type;
  }

  return os;
}
}
}
