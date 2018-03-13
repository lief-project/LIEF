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
#include <iomanip>

#include "LIEF/exception.hpp"
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersion.hpp"


namespace LIEF {
namespace ELF {

SymbolVersion::SymbolVersion(void) :
  value_{0},
  symbol_aux_{nullptr}
{}

SymbolVersion::~SymbolVersion(void) = default;

SymbolVersion& SymbolVersion::operator=(const SymbolVersion&) = default;

SymbolVersion::SymbolVersion(const SymbolVersion&) = default;

SymbolVersion::SymbolVersion(uint16_t value) :
  value_{value},
  symbol_aux_{nullptr}
{}


SymbolVersion SymbolVersion::local(void) {
  return SymbolVersion{0};
}

SymbolVersion SymbolVersion::global(void) {
  return SymbolVersion{1};
}

uint16_t SymbolVersion::value(void) const {
  return this->value_;
}


bool SymbolVersion::has_auxiliary_version(void) const {
  return this->symbol_aux_ != nullptr;
}

const SymbolVersionAux& SymbolVersion::symbol_version_auxiliary(void) const {
  if (this->symbol_aux_ != nullptr) {
    return *this->symbol_aux_;
  } else {
    throw not_found("No auxiliary symbol associated with this version");
  }

}

SymbolVersionAux& SymbolVersion::symbol_version_auxiliary(void) {
  return const_cast<SymbolVersionAux&>(static_cast<const SymbolVersion*>(this)->symbol_version_auxiliary());
}

void SymbolVersion::value(uint16_t value) {
  this->value_ = value;
}

void SymbolVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersion::operator==(const SymbolVersion& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersion::operator!=(const SymbolVersion& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ELF::SymbolVersion& symv) {
  if (symv.has_auxiliary_version()) {
    os << symv.symbol_version_auxiliary().name() << "(" << symv.value() << ")";
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
