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
#include <algorithm>
#include <iostream>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/EnumToString.hpp"

namespace LIEF {
namespace PE {

Symbol::Symbol(void) :
  value_{0},
  section_number_{0},
  type_{0},
  storage_class_{SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_INVALID},
  numberof_aux_symbols_{0},
  section_{nullptr}
{}

Symbol::~Symbol(void) = default;

Symbol::Symbol(const Symbol& other) :
  LIEF::Symbol{other},
  value_{other.value_},
  section_number_{other.section_number_},
  type_{other.type_},
  storage_class_{other.storage_class_},
  numberof_aux_symbols_{other.numberof_aux_symbols_},
  section_{nullptr}
{}


Symbol& Symbol::operator=(Symbol other) {
  this->swap(other);
  return *this;
}

void Symbol::swap(Symbol& other) {
  std::swap(this->value_,                 other.value_);
  std::swap(this->section_number_,        other.section_number_);
  std::swap(this->type_,                  other.type_);
  std::swap(this->storage_class_,         other.storage_class_);
  std::swap(this->numberof_aux_symbols_,  other.numberof_aux_symbols_);
  std::swap(this->section_,               other.section_);
}

Symbol::Symbol(const pe_symbol* header) :
  value_(header->Value),
  section_number_(header->SectionNumber),
  type_(header->Type),
  storage_class_(static_cast<SYMBOL_STORAGE_CLASS>(header->StorageClass)),
  numberof_aux_symbols_(header->NumberOfAuxSymbols),
  section_{nullptr}
{}


uint32_t Symbol::value(void) const {
  return this->value_;
}

int16_t Symbol::section_number(void) const {
  return this->section_number_;
}

uint16_t Symbol::type(void) const {
  return this->type_;
}

SYMBOL_BASE_TYPES Symbol::base_type(void) const {
  return static_cast<SYMBOL_BASE_TYPES>(this->type_ & 0x0F);
}

SYMBOL_COMPLEX_TYPES Symbol::complex_type(void) const {
  return static_cast<SYMBOL_COMPLEX_TYPES>((this->type_ >> 4) & 0x0F);
}


SYMBOL_STORAGE_CLASS Symbol::storage_class(void) const {
  return this->storage_class_;
}


uint8_t Symbol::numberof_aux_symbols(void) const {
  return this->numberof_aux_symbols_;
}


std::wstring Symbol::wname(void) const {
  return {std::begin(this->name_), std::end(this->name_)};
}


const Section& Symbol::section(void) const {
  if (this->has_section()) {
    return *(this->section_);
  } else {
    throw not_found("No section associated with this symbol");
  }
}

Section& Symbol::section(void) {
  return const_cast<Section&>(static_cast<const Symbol*>(this)->section());
}

bool Symbol::has_section(void) const {
  return this->section_ != nullptr;
}

void Symbol::accept(LIEF::Visitor& visitor) const {
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
  std::string section_number_str = "";
  if (entry.section_number() <= 0) {
    section_number_str = to_string(
        static_cast<SYMBOL_SECTION_NUMBER>(entry.section_number()));
  } else {
    if (entry.has_section()) {
      section_number_str = entry.section().name();
    } else {
      section_number_str = std::to_string(static_cast<uint32_t>(entry.section_number())); // section
    }
  }

  std::string name = entry.name();
  // UTF8 -> ASCII
  std::transform(
      std::begin(name),
      std::end(name),
      std::begin(name),
      [] (char c) {
        return (c <= '~' and c >= '!') ? c : ' ';
      });

  if (name.size() > 20) {
    name = name.substr(0, 17) + "...";
  }


  os << std::hex;
  os << std::left
     << std::setw(30) << name
     << std::setw(10) << entry.value()
     << std::setw(20) << section_number_str
     << std::setw(10) << to_string(entry.base_type())
     << std::setw(10) << to_string(entry.complex_type())
     << std::setw(10) << to_string(entry.storage_class());

  return os;
}

}
}
