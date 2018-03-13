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
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

namespace LIEF {
namespace ELF {

SymbolVersionAuxRequirement::SymbolVersionAuxRequirement(void) :
  hash_{0},
  flags_{0},
  other_{0}
{}

SymbolVersionAuxRequirement::~SymbolVersionAuxRequirement(void) = default;
SymbolVersionAuxRequirement& SymbolVersionAuxRequirement::operator=(const SymbolVersionAuxRequirement&) = default;
SymbolVersionAuxRequirement::SymbolVersionAuxRequirement(const SymbolVersionAuxRequirement&) = default;


SymbolVersionAuxRequirement::SymbolVersionAuxRequirement(const Elf64_Vernaux* header) :
  hash_{header->vna_hash},
  flags_{header->vna_flags},
  other_{header->vna_other}
{}


SymbolVersionAuxRequirement::SymbolVersionAuxRequirement(const Elf32_Vernaux* header) :
  hash_{header->vna_hash},
  flags_{header->vna_flags},
  other_{header->vna_other}
{}


uint32_t SymbolVersionAuxRequirement::hash(void) const {
  return this->hash_;
}


uint16_t SymbolVersionAuxRequirement::flags(void) const {
  return this->flags_;
}


uint16_t SymbolVersionAuxRequirement::other(void) const {
  return this->other_;
}


void SymbolVersionAuxRequirement::hash(uint32_t hash) {
  this->hash_ = hash;
}


void SymbolVersionAuxRequirement::flags(uint16_t flags) {
  this->flags_ = flags;
}


void SymbolVersionAuxRequirement::other(uint16_t other) {
  this->other_ = other;
}

void SymbolVersionAuxRequirement::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersionAuxRequirement::operator==(const SymbolVersionAuxRequirement& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersionAuxRequirement::operator!=(const SymbolVersionAuxRequirement& rhs) const {
  return not (*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const SymbolVersionAuxRequirement& symAux) {
  os << symAux.name();
  return os;
}
}
}
