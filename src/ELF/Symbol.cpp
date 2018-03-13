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

#ifdef __unix__
  #include <cxxabi.h>
#endif

#include "LIEF/exception.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/EnumToString.hpp"


namespace LIEF {
namespace ELF {

Symbol::Symbol(void) :
  type_{ELF_SYMBOL_TYPES::STT_NOTYPE},
  binding_{SYMBOL_BINDINGS::STB_LOCAL},
  other_{0},
  shndx_{0},
  value_{0},
  size_{0},
  symbol_version_{nullptr}
{}


Symbol::~Symbol(void) = default;

Symbol& Symbol::operator=(Symbol other) {
  this->swap(other);
  return *this;
}

Symbol::Symbol(const Symbol& other) : LIEF::Symbol{other},
  type_{other.type_},
  binding_{other.binding_},
  other_{other.other_},
  shndx_{other.shndx_},
  value_{other.value_},
  size_{other.size_},
  symbol_version_{nullptr}
{}


void Symbol::swap(Symbol& other) {
  std::swap(this->name_,           other.name_);
  std::swap(this->type_,           other.type_);
  std::swap(this->binding_,        other.binding_);
  std::swap(this->other_,          other.other_);
  std::swap(this->shndx_,          other.shndx_);
  std::swap(this->value_,          other.value_);
  std::swap(this->size_,           other.size_);
  std::swap(this->symbol_version_, other.symbol_version_);
}

Symbol::Symbol(const Elf32_Sym* header) :
  LIEF::Symbol{},
  type_{static_cast<ELF_SYMBOL_TYPES>(header->st_info & 0x0f)},
  binding_{static_cast<SYMBOL_BINDINGS>(header->st_info >> 4)},
  other_{header->st_other},
  shndx_{header->st_shndx},
  value_{header->st_value},
  size_{header->st_size},
  symbol_version_{nullptr}
{}

Symbol::Symbol(const Elf64_Sym* header) :
  LIEF::Symbol{},
  type_{static_cast<ELF_SYMBOL_TYPES>(header->st_info & 0x0f)},
  binding_{static_cast<SYMBOL_BINDINGS>(header->st_info >> 4)},
  other_{header->st_other},
  shndx_{header->st_shndx},
  value_{header->st_value},
  size_{header->st_size},
  symbol_version_{nullptr}
{}


Symbol::Symbol(std::string name, ELF_SYMBOL_TYPES type, SYMBOL_BINDINGS binding,
    uint8_t other, uint16_t shndx,
    uint64_t value, uint64_t size) :
  LIEF::Symbol{name},
  type_{type},
  binding_{binding},
  other_{other},
  shndx_{shndx},
  value_{value},
  size_{size},
  symbol_version_{nullptr}
{}


ELF_SYMBOL_TYPES Symbol::type(void) const {
  return this->type_;
}

SYMBOL_BINDINGS Symbol::binding(void) const {
  return this->binding_;
}

uint8_t Symbol::information(void) const {
  return static_cast<uint8_t>((static_cast<uint8_t>(this->binding_) << 4) | (static_cast<uint8_t>(this->type_) & 0x0f));
}

uint8_t Symbol::other(void) const {
  return this->other_;
}

uint16_t Symbol::section_idx(void) const {
  return this->shndx();
}

Section& Symbol::section(void) {
  if (this->section_ == nullptr) {
    throw not_found("No section associated with this symbol");
  } else {
    return *this->section_;
  }
}

uint64_t Symbol::value(void) const {
  return this->value_;
}

uint64_t Symbol::size(void) const {
  return this->size_;
}

uint16_t Symbol::shndx(void) const {
  return this->shndx_;
}


ELF_SYMBOL_VISIBILITY Symbol::visibility(void) const {
  return static_cast<ELF_SYMBOL_VISIBILITY>(this->other_);
}


bool Symbol::has_version(void) const {
  return this->symbol_version_ != nullptr;
}


const SymbolVersion& Symbol::symbol_version(void) const {
  if (this->symbol_version_ != nullptr) {
    return *this->symbol_version_;
  } else {
    throw not_found("There is no symbol version associated with this symbol");
  }
}

SymbolVersion& Symbol::symbol_version(void) {
  return const_cast<SymbolVersion&>(static_cast<const Symbol*>(this)->symbol_version());
}

void Symbol::type(ELF_SYMBOL_TYPES type) {
  this->type_ = type;
}

void Symbol::binding(SYMBOL_BINDINGS binding) {
  this->binding_ = binding;
}

void Symbol::other(uint8_t other) {
  this->other_ = other;
}

void Symbol::value(uint64_t value) {
  this->value_ = value;
}

void Symbol::size(uint64_t size) {
  this->size_ = size;
}


void Symbol::shndx(uint16_t idx) {
  this->shndx_ = idx;
}

void Symbol::visibility(ELF_SYMBOL_VISIBILITY visibility) {
  this->other_ = static_cast<uint8_t>(visibility);
}


void Symbol::information(uint8_t info) {
  this->binding_ = static_cast<SYMBOL_BINDINGS>(info >> 4);
  this->type_    = static_cast<ELF_SYMBOL_TYPES>(info & 0x0f);
}


std::string Symbol::demangled_name(void) const {
#if defined(__unix__)
  int status;
  const std::string& name = this->name().c_str();
  auto realname = abi::__cxa_demangle(name.c_str(), 0, 0, &status);

  if (status == 0) {
    return realname;
  } else {
    return name;
  }
#else
  throw not_supported("Can't demangle name");
#endif
}

bool Symbol::is_exported(void) const {
  bool is_exported = this->shndx() != static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF);

  // An export must have an address
  is_exported = is_exported and this->value() != 0;

  // An export must be bind to GLOBAL or WEAK
  is_exported = is_exported and (this->binding() == SYMBOL_BINDINGS::STB_GLOBAL or
                                 this->binding() == SYMBOL_BINDINGS::STB_WEAK);

  // An export must have one of theses types:
  is_exported = is_exported and (this->type() == ELF_SYMBOL_TYPES::STT_FUNC or
                                 this->type() == ELF_SYMBOL_TYPES::STT_GNU_IFUNC or
                                 this->type() == ELF_SYMBOL_TYPES::STT_OBJECT);
  return is_exported;
}

void Symbol::set_exported(bool flag) {
  if (flag) {
    this->shndx(1);
    this->binding(SYMBOL_BINDINGS::STB_GLOBAL);
  } else {
    this->shndx(SYMBOL_SECTION_INDEX::SHN_UNDEF);
    this->binding(SYMBOL_BINDINGS::STB_LOCAL);
  }
}

bool Symbol::is_imported(void) const {
  // An import must not be defined in a section
  bool is_imported = this->shndx() == static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF);

  // An import must not have an address
  is_imported = is_imported and this->value() == 0;

  // its name must not be empty
  is_imported = is_imported and not this->name().empty();

  // It must have a GLOBAL or WEAK bind
  is_imported = is_imported and (this->binding() == SYMBOL_BINDINGS::STB_GLOBAL or
                                 this->binding() == SYMBOL_BINDINGS::STB_WEAK);

  // It must be a FUNC or an OBJECT
  is_imported = is_imported and (this->type() == ELF_SYMBOL_TYPES::STT_FUNC or
                                 this->type() == ELF_SYMBOL_TYPES::STT_GNU_IFUNC or
                                 this->type() == ELF_SYMBOL_TYPES::STT_OBJECT);
  return is_imported;
}

void Symbol::set_imported(bool flag) {
  if (flag) {
    this->shndx(SYMBOL_SECTION_INDEX::SHN_UNDEF);
  } else {
    this->shndx(1);
  }
}



void Symbol::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Symbol::operator==(const Symbol& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Symbol::operator!=(const Symbol& rhs) const {
  return not (*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const Symbol& entry) {

  std::string name;
  try {
    name = entry.demangled_name();
  } catch (const not_supported&) {
    name = entry.name();
  }
  os << std::hex;
  os << std::left
     << std::setw(30) << name
     << std::setw(10) << to_string(entry.type())
     << std::setw(10) << to_string(entry.binding())
     << std::setw(10) << entry.value()
     << std::setw(10) << entry.size();

  if (entry.has_version()) {
    os << std::setw(10) << entry.symbol_version();
  }

  return os;
}
}
}
