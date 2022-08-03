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
#include <utility>

#ifdef __unix__
  #include <cxxabi.h>
#endif

#include "LIEF/exception.hpp"

#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"

#include "ELF/Structures.hpp"

namespace LIEF {
namespace ELF {

Symbol::Symbol() = default;
Symbol::~Symbol() = default;

Symbol& Symbol::operator=(Symbol other) {
  swap(other);
  return *this;
}

Symbol::Symbol(const Symbol& other) : LIEF::Symbol{other},
  type_{other.type_},
  binding_{other.binding_},
  other_{other.other_},
  shndx_{other.shndx_}
{}


void Symbol::swap(Symbol& other) {
  LIEF::Symbol::swap(other);
  std::swap(type_,           other.type_);
  std::swap(binding_,        other.binding_);
  std::swap(other_,          other.other_);
  std::swap(shndx_,          other.shndx_);
  std::swap(section_,        other.section_);
  std::swap(symbol_version_, other.symbol_version_);
}

Symbol::Symbol(const details::Elf32_Sym& header) :
  type_{static_cast<ELF_SYMBOL_TYPES>(header.st_info & 0x0f)},
  binding_{static_cast<SYMBOL_BINDINGS>(header.st_info >> 4)},
  other_{header.st_other},
  shndx_{header.st_shndx}
{
  value_ = header.st_value;
  size_  = header.st_size;
}

Symbol::Symbol(const details::Elf64_Sym& header) :
  type_{static_cast<ELF_SYMBOL_TYPES>(header.st_info & 0x0f)},
  binding_{static_cast<SYMBOL_BINDINGS>(header.st_info >> 4)},
  other_{header.st_other},
  shndx_{header.st_shndx}
{
  value_ = header.st_value;
  size_  = header.st_size;
}


Symbol::Symbol(std::string name, ELF_SYMBOL_TYPES type, SYMBOL_BINDINGS binding,
    uint8_t other, uint16_t shndx,
    uint64_t value, uint64_t size) :
  LIEF::Symbol{std::move(name), value, size},
  type_{type},
  binding_{binding},
  other_{other},
  shndx_{shndx}
{}


ELF_SYMBOL_TYPES Symbol::type() const {
  return type_;
}

SYMBOL_BINDINGS Symbol::binding() const {
  return binding_;
}

uint8_t Symbol::information() const {
  return static_cast<uint8_t>((static_cast<uint8_t>(binding_) << 4) | (static_cast<uint8_t>(type_) & 0x0f));
}

uint8_t Symbol::other() const {
  return other_;
}

uint16_t Symbol::section_idx() const {
  return shndx();
}

Section* Symbol::section() {
  return section_;
}

uint16_t Symbol::shndx() const {
  return shndx_;
}


ELF_SYMBOL_VISIBILITY Symbol::visibility() const {
  return static_cast<ELF_SYMBOL_VISIBILITY>(other_);
}


bool Symbol::has_version() const {
  return symbol_version_ != nullptr;
}


const SymbolVersion* Symbol::symbol_version() const {
  return symbol_version_;
}

SymbolVersion* Symbol::symbol_version() {
  return const_cast<SymbolVersion*>(static_cast<const Symbol*>(this)->symbol_version());
}

void Symbol::type(ELF_SYMBOL_TYPES type) {
  type_ = type;
}

void Symbol::binding(SYMBOL_BINDINGS binding) {
  binding_ = binding;
}

void Symbol::other(uint8_t other) {
  other_ = other;
}

void Symbol::shndx(uint16_t idx) {
  shndx_ = idx;
}

void Symbol::visibility(ELF_SYMBOL_VISIBILITY visibility) {
  other_ = static_cast<uint8_t>(visibility);
}


void Symbol::information(uint8_t info) {
  binding_ = static_cast<SYMBOL_BINDINGS>(info >> 4);
  type_    = static_cast<ELF_SYMBOL_TYPES>(info & 0x0f);
}


std::string Symbol::demangled_name() const {
#if defined(__unix__)
  int status;
  const std::string& name = this->name().c_str();
  char* demangled_name = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);

  if (status == 0) {
    std::string realname = demangled_name;
    free(demangled_name);
    return realname;
  }

  return name;
#else
  return "";
#endif
}

bool Symbol::is_exported() const {
  bool is_exported = shndx() != static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF);

  // An export must have an address
  is_exported = is_exported && (value() != 0 || (value() == 0 && size() > 0));

  // An export must be bind to GLOBAL or WEAK
  is_exported = is_exported && (binding() == SYMBOL_BINDINGS::STB_GLOBAL ||
                                binding() == SYMBOL_BINDINGS::STB_WEAK);

  // An export must have one of theses types:
  is_exported = is_exported && (type() == ELF_SYMBOL_TYPES::STT_FUNC ||
                                type() == ELF_SYMBOL_TYPES::STT_GNU_IFUNC ||
                                type() == ELF_SYMBOL_TYPES::STT_OBJECT);
  return is_exported;
}

void Symbol::set_exported(bool flag) {
  if (flag) {
    shndx(1);
    binding(SYMBOL_BINDINGS::STB_GLOBAL);
  } else {
    shndx(SYMBOL_SECTION_INDEX::SHN_UNDEF);
    binding(SYMBOL_BINDINGS::STB_LOCAL);
  }
}

bool Symbol::is_imported() const {
  // An import must not be defined in a section
  bool is_imported = shndx() == static_cast<uint16_t>(SYMBOL_SECTION_INDEX::SHN_UNDEF);

  // An import must not have an address
  is_imported = is_imported && value() == 0;

  // its name must not be empty
  is_imported = is_imported && !name().empty();

  // It must have a GLOBAL or WEAK bind
  is_imported = is_imported && (binding() == SYMBOL_BINDINGS::STB_GLOBAL ||
                                 binding() == SYMBOL_BINDINGS::STB_WEAK);

  // It must be a FUNC or an OBJECT
  is_imported = is_imported && (type() == ELF_SYMBOL_TYPES::STT_FUNC ||
                                 type() == ELF_SYMBOL_TYPES::STT_GNU_IFUNC ||
                                 type() == ELF_SYMBOL_TYPES::STT_OBJECT);
  return is_imported;
}

void Symbol::set_imported(bool flag) {
  if (flag) {
    shndx(SYMBOL_SECTION_INDEX::SHN_UNDEF);
  } else {
    shndx(1);
  }
}



void Symbol::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool Symbol::operator==(const Symbol& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Symbol::operator!=(const Symbol& rhs) const {
  return !(*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const Symbol& entry) {

  std::string name = entry.demangled_name();
  if (name.empty()) {
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
