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
#include <algorithm>
#include <iterator>

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"

#include "ELF/Structures.hpp"

namespace LIEF {
namespace ELF {

SymbolVersionRequirement::SymbolVersionRequirement() = default;
SymbolVersionRequirement::~SymbolVersionRequirement() = default;


SymbolVersionRequirement::SymbolVersionRequirement(const details::Elf64_Verneed& header) :
  version_{header.vn_version}
{}

SymbolVersionRequirement::SymbolVersionRequirement(const details::Elf32_Verneed& header)  :
  version_{header.vn_version}
{}


SymbolVersionRequirement::SymbolVersionRequirement(const SymbolVersionRequirement& other) :
  Object{other},
  version_{other.version_},
  name_{other.name_}
{
  aux_requirements_.reserve(other.aux_requirements_.size());
  for (const std::unique_ptr<SymbolVersionAuxRequirement>& aux : other.aux_requirements_) {
    aux_requirements_.push_back(std::make_unique<SymbolVersionAuxRequirement>(*aux));
  }
}


SymbolVersionRequirement& SymbolVersionRequirement::operator=(SymbolVersionRequirement other) {
  swap(other);
  return *this;
}

void SymbolVersionRequirement::swap(SymbolVersionRequirement& other) {
  std::swap(aux_requirements_, other.aux_requirements_);
  std::swap(version_,          other.version_);
  std::swap(name_,             other.name_);
}


uint16_t SymbolVersionRequirement::version() const {
  return version_;
}


uint32_t SymbolVersionRequirement::cnt() const {
  return static_cast<uint32_t>(aux_requirements_.size());
}


SymbolVersionRequirement::it_aux_requirement SymbolVersionRequirement::auxiliary_symbols() {
  return aux_requirements_;
}


SymbolVersionRequirement::it_const_aux_requirement SymbolVersionRequirement::auxiliary_symbols() const {
  return aux_requirements_;
}


const std::string& SymbolVersionRequirement::name() const {
  return name_;
}


void SymbolVersionRequirement::version(uint16_t version) {
  version_ = version;
}


void SymbolVersionRequirement::name(const std::string& name) {
  name_ = name;
}

SymbolVersionAuxRequirement& SymbolVersionRequirement::add_aux_requirement(const SymbolVersionAuxRequirement& aux_requirement) {
  aux_requirements_.push_back(std::make_unique<SymbolVersionAuxRequirement>(aux_requirement));
  return *aux_requirements_.back();
}

void SymbolVersionRequirement::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool SymbolVersionRequirement::operator==(const SymbolVersionRequirement& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SymbolVersionRequirement::operator!=(const SymbolVersionRequirement& rhs) const {
  return !(*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const SymbolVersionRequirement& symr) {
  os << symr.version() << " " << symr.name();

  return os;
}
}
}
