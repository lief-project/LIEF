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
#include <algorithm>
#include <iterator>

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersionRequirement.hpp"

namespace LIEF {
namespace ELF {

SymbolVersionRequirement::SymbolVersionRequirement(void) :
  symbol_version_aux_requirement_{},
  version_{0},
  name_{""}
{}


SymbolVersionRequirement::~SymbolVersionRequirement(void) {
  for (SymbolVersionAuxRequirement* svar : this->symbol_version_aux_requirement_) {
    delete svar;
  }
}


SymbolVersionRequirement::SymbolVersionRequirement(const Elf64_Verneed *header) :
  symbol_version_aux_requirement_{},
  version_{header->vn_version},
  name_{""}
{}

SymbolVersionRequirement::SymbolVersionRequirement(const Elf32_Verneed *header)  :
  symbol_version_aux_requirement_{},
  version_{header->vn_version},
  name_{""}
{}


SymbolVersionRequirement::SymbolVersionRequirement(const SymbolVersionRequirement& other) :
  Object{other},
  version_{other.version_},
  name_{other.name_}
{
  symbol_version_aux_requirement_.reserve(other.symbol_version_aux_requirement_.size());
  for (const SymbolVersionAuxRequirement* aux : other.symbol_version_aux_requirement_) {
    this->symbol_version_aux_requirement_.push_back(new SymbolVersionAuxRequirement{*aux});
  }
}


SymbolVersionRequirement& SymbolVersionRequirement::operator=(SymbolVersionRequirement other) {
  this->swap(other);
  return *this;
}

void SymbolVersionRequirement::swap(SymbolVersionRequirement& other) {
  std::swap(this->symbol_version_aux_requirement_, other.symbol_version_aux_requirement_);
  std::swap(this->version_,                        other.version_);
  std::swap(this->name_,                           other.name_);
}


uint16_t SymbolVersionRequirement::version(void) const {
  return this->version_;
}


uint32_t SymbolVersionRequirement::cnt(void) const {
  return static_cast<uint32_t>(this->symbol_version_aux_requirement_.size());
}


it_symbols_version_aux_requirement SymbolVersionRequirement::auxiliary_symbols(void) {
  return this->symbol_version_aux_requirement_;
}


it_const_symbols_version_aux_requirement SymbolVersionRequirement::auxiliary_symbols(void) const {
  return this->symbol_version_aux_requirement_;
}


const std::string& SymbolVersionRequirement::name(void) const {
  return this->name_;
}


void SymbolVersionRequirement::version(uint16_t version) {
  this->version_ = version;
}


void SymbolVersionRequirement::name(const std::string& name) {
  this->name_ = name;
}


void SymbolVersionRequirement::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersionRequirement::operator==(const SymbolVersionRequirement& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersionRequirement::operator!=(const SymbolVersionRequirement& rhs) const {
  return not (*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const SymbolVersionRequirement& symr) {
  os << symr.version() << " " << symr.name();

  return os;
}
}
}
