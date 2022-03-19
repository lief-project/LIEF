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
#include "LIEF/ELF/SymbolVersionDefinition.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <iterator>

#include "ELF/Structures.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/hash.hpp"

namespace LIEF {
namespace ELF {

SymbolVersionDefinition::SymbolVersionDefinition() = default;
SymbolVersionDefinition::~SymbolVersionDefinition() = default;

SymbolVersionDefinition::SymbolVersionDefinition(
    const details::Elf64_Verdef& header)
    : version_{header.vd_version},
      flags_{header.vd_flags},
      ndx_{header.vd_ndx},
      hash_{header.vd_hash} {}

SymbolVersionDefinition::SymbolVersionDefinition(
    const details::Elf32_Verdef& header)
    : version_{header.vd_version},
      flags_{header.vd_flags},
      ndx_{header.vd_ndx},
      hash_{header.vd_hash} {}

SymbolVersionDefinition::SymbolVersionDefinition(
    const SymbolVersionDefinition& other)
    : Object{other},
      version_{other.version_},
      flags_{other.flags_},
      ndx_{other.ndx_},
      hash_{other.hash_} {
  symbol_version_aux_.reserve(other.symbol_version_aux_.size());
  for (const std::unique_ptr<SymbolVersionAux>& aux :
       other.symbol_version_aux_) {
    symbol_version_aux_.emplace_back(new SymbolVersionAux{*aux});
  }
}

SymbolVersionDefinition& SymbolVersionDefinition::operator=(
    SymbolVersionDefinition other) {
  swap(other);
  return *this;
}

void SymbolVersionDefinition::swap(SymbolVersionDefinition& other) {
  std::swap(version_, other.version_);
  std::swap(flags_, other.flags_);
  std::swap(ndx_, other.ndx_);
  std::swap(hash_, other.hash_);
  std::swap(symbol_version_aux_, other.symbol_version_aux_);
}

uint16_t SymbolVersionDefinition::version() const { return version_; }

uint16_t SymbolVersionDefinition::flags() const { return flags_; }

uint16_t SymbolVersionDefinition::ndx() const { return ndx_; }

uint32_t SymbolVersionDefinition::hash() const { return hash_; }

SymbolVersionDefinition::it_version_aux SymbolVersionDefinition::symbols_aux() {
  return symbol_version_aux_;
}

SymbolVersionDefinition::it_const_version_aux
SymbolVersionDefinition::symbols_aux() const {
  return symbol_version_aux_;
}

void SymbolVersionDefinition::version(uint16_t version) { version_ = version; }

void SymbolVersionDefinition::flags(uint16_t flags) { flags_ = flags; }

void SymbolVersionDefinition::hash(uint32_t hash) { hash_ = hash; }

void SymbolVersionDefinition::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersionDefinition::operator==(
    const SymbolVersionDefinition& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersionDefinition::operator!=(
    const SymbolVersionDefinition& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const SymbolVersionDefinition& sym) {
  os << std::hex << std::left;
  os << std::setw(10) << sym.version();
  os << std::setw(10) << sym.flags();
  os << std::setw(10) << sym.ndx();
  os << std::setw(10) << sym.hash();

  return os;
}
}  // namespace ELF
}  // namespace LIEF
