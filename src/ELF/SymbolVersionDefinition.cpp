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
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <iterator>

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

namespace LIEF {
namespace ELF {

SymbolVersionDefinition::SymbolVersionDefinition(void) :
  version_{1},
  flags_{0},
  ndx_{0},
  hash_{0},
  symbol_version_aux_{}
{}

SymbolVersionDefinition::SymbolVersionDefinition(const Elf64_Verdef *header) :
  version_{header->vd_version},
  flags_{header->vd_flags},
  ndx_{header->vd_ndx},
  hash_{header->vd_hash},
  symbol_version_aux_{}
{}

SymbolVersionDefinition::SymbolVersionDefinition(const Elf32_Verdef *header) :
  version_{header->vd_version},
  flags_{header->vd_flags},
  ndx_{header->vd_ndx},
  hash_{header->vd_hash},
  symbol_version_aux_{}
{}


SymbolVersionDefinition::SymbolVersionDefinition(const SymbolVersionDefinition& other) :
  Object{other},
  version_{other.version_},
  flags_{other.flags_},
  ndx_{other.ndx_},
  hash_{other.hash_},
  symbol_version_aux_{}
{
  this->symbol_version_aux_.reserve(other.symbol_version_aux_.size());
  for (const SymbolVersionAux* aux : other.symbol_version_aux_) {
    this->symbol_version_aux_.push_back(new SymbolVersionAux{*aux});
  }
}

SymbolVersionDefinition& SymbolVersionDefinition::operator=(SymbolVersionDefinition other) {
  this->swap(other);
  return *this;
}

SymbolVersionDefinition::~SymbolVersionDefinition(void) {
  for (SymbolVersionAux* sva : this->symbol_version_aux_) {
    delete sva;
  }
}

void SymbolVersionDefinition::swap(SymbolVersionDefinition& other) {
  std::swap(this->version_,            other.version_);
  std::swap(this->flags_,              other.flags_);
  std::swap(this->ndx_,                other.ndx_);
  std::swap(this->hash_,               other.hash_);
  std::swap(this->symbol_version_aux_, other.symbol_version_aux_);
}


uint16_t SymbolVersionDefinition::version(void) const {
  return this->version_;
}

uint16_t SymbolVersionDefinition::flags(void) const {
  return this->flags_;
}

uint16_t SymbolVersionDefinition::ndx(void) const {
  return this->ndx_;
}

uint32_t SymbolVersionDefinition::hash(void) const {
  return this->hash_;
}

it_symbols_version_aux SymbolVersionDefinition::symbols_aux(void) {
  return this->symbol_version_aux_;
}

it_const_symbols_version_aux SymbolVersionDefinition::symbols_aux(void) const {
  return this->symbol_version_aux_;

}

void SymbolVersionDefinition::version(uint16_t version) {
  this->version_ = version;
}

void SymbolVersionDefinition::flags(uint16_t flags) {
  this->flags_ = flags;
}

void SymbolVersionDefinition::hash(uint32_t hash) {
  this->hash_ = hash;
}

void SymbolVersionDefinition::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool SymbolVersionDefinition::operator==(const SymbolVersionDefinition& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersionDefinition::operator!=(const SymbolVersionDefinition& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const SymbolVersionDefinition& sym) {
  os << std::hex << std::left;
  os << std::setw(10) << sym.version();
  os << std::setw(10) << sym.flags();
  os << std::setw(10) << sym.ndx();
  os << std::setw(10) << sym.hash();

  return os;
}
}
}
