/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <ostream>

#include "LIEF/PE/hash.hpp"


#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

Symbol::Symbol() = default;
Symbol::~Symbol() = default;

Symbol::Symbol(const Symbol&) = default;

Symbol& Symbol::operator=(Symbol other) {
  swap(other);
  return *this;
}

void Symbol::swap(Symbol& other) {
  LIEF::Symbol::swap(other);

  std::swap(section_number_,        other.section_number_);
  std::swap(type_,                  other.type_);
  std::swap(storage_class_,         other.storage_class_);
  std::swap(numberof_aux_symbols_,  other.numberof_aux_symbols_);
  std::swap(section_,               other.section_);
}

Symbol::Symbol(const details::pe_symbol& header) :
  section_number_(header.SectionNumber),
  type_(header.Type),
  numberof_aux_symbols_(header.NumberOfAuxSymbols),
  storage_class_(static_cast<SYMBOL_STORAGE_CLASS>(header.StorageClass))
{
  value_ = header.Value;
}


int16_t Symbol::section_number() const {
  return section_number_;
}

uint16_t Symbol::type() const {
  return type_;
}

SYMBOL_BASE_TYPES Symbol::base_type() const {
  return static_cast<SYMBOL_BASE_TYPES>(type_ & 0x0F);
}

SYMBOL_COMPLEX_TYPES Symbol::complex_type() const {
  return static_cast<SYMBOL_COMPLEX_TYPES>((type_ >> 4) & 0x0F);
}


SYMBOL_STORAGE_CLASS Symbol::storage_class() const {
  return storage_class_;
}


uint8_t Symbol::numberof_aux_symbols() const {
  return numberof_aux_symbols_;
}


std::wstring Symbol::wname() const {
  return {std::begin(name_), std::end(name_)};
}

const Section* Symbol::section() const {
  return section_;
}

Section* Symbol::section() {
  return const_cast<Section*>(static_cast<const Symbol*>(this)->section());
}

bool Symbol::has_section() const {
  return section_ != nullptr;
}

void Symbol::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}




std::ostream& operator<<(std::ostream& os, const Symbol& entry) {
  std::string section_number_str;
  if (entry.section_number() <= 0) {
    section_number_str = to_string(
        static_cast<SYMBOL_SECTION_NUMBER>(entry.section_number()));
  } else {
    if (entry.has_section()) {
      section_number_str = entry.section()->name();
    } else {
      section_number_str = std::to_string(static_cast<uint32_t>(entry.section_number())); // section
    }
  }

  std::string name = entry.name();
  // UTF8 -> ASCII
  std::transform(std::begin(name), std::end(name),
      std::begin(name),
      [] (char c) {
        return (c <= '~' && c >= '!') ? c : ' ';
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
