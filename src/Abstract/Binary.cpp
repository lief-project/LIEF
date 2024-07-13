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
#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/Visitor.hpp"

#include "logging.hpp"
#include "frozen.hpp"

#include "LIEF/Abstract/Section.hpp"
#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/Abstract/DebugInfo.hpp"

namespace LIEF {

Binary::Binary(FORMATS fmt) :
  format_{fmt}
{}

Binary::Binary() = default;

Binary::~Binary() = default;

Header Binary::header() const {
  return get_abstract_header();
}

Binary::it_symbols Binary::symbols() {
  return get_abstract_symbols();
}

Binary::it_const_symbols Binary::symbols() const {
  return const_cast<Binary*>(this)->get_abstract_symbols();
}


bool Binary::has_symbol(const std::string& name) const {
  return get_symbol(name) != nullptr;
}

const Symbol* Binary::get_symbol(const std::string& name) const {
  symbols_t symbols = const_cast<Binary*>(this)->get_abstract_symbols();
  const auto it_symbol = std::find_if(std::begin(symbols), std::end(symbols),
                                      [&name] (const Symbol* s) {
                                        return s->name() == name;
                                      });

  if (it_symbol == std::end(symbols)) {
    return nullptr;
  }

  return *it_symbol;
}

Symbol* Binary::get_symbol(const std::string& name) {
  return const_cast<Symbol*>(static_cast<const Binary*>(this)->get_symbol(name));
}

Binary::it_sections Binary::sections() {
  return get_abstract_sections();
}


Binary::it_const_sections Binary::sections() const {
  return const_cast<Binary*>(this)->get_abstract_sections();
}


Binary::it_relocations Binary::relocations() {
  return get_abstract_relocations();
}

Binary::it_const_relocations Binary::relocations() const {
  return const_cast<Binary*>(this)->get_abstract_relocations();
}


Binary::functions_t Binary::exported_functions() const {
  return get_abstract_exported_functions();
}

Binary::functions_t Binary::imported_functions() const {
  return get_abstract_imported_functions();
}


std::vector<std::string> Binary::imported_libraries() const {
  return get_abstract_imported_libraries();
}

result<uint64_t> Binary::get_function_address(const std::string&) const {
  LIEF_ERR("Not implemented for this format");
  return make_error_code(lief_errors::not_implemented);
}

std::vector<uint64_t> Binary::xref(uint64_t address) const {
  std::vector<uint64_t> result;

  for (Section* section : const_cast<Binary*>(this)->get_abstract_sections()) {
    std::vector<size_t> founds = section->search_all(address);
    for (size_t found : founds) {
      result.push_back(section->virtual_address() + found);
    }
  }

  return result;
}

void Binary::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& Binary::print(std::ostream& os) const {
  return os;
}

std::ostream& operator<<(std::ostream& os, const Binary& binary) {
  binary.print(os);
  return os;
}

const char* to_string(Binary::VA_TYPES e) {
  #define ENTRY(X) std::pair(Binary::VA_TYPES::X, #X)
  STRING_MAP enums2str {
    ENTRY(AUTO),
    ENTRY(RVA),
    ENTRY(VA),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }

  return "UNKNOWN";
}

const char* to_string(Binary::FORMATS e) {
  #define ENTRY(X) std::pair(Binary::FORMATS::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNKNOWN),
    ENTRY(ELF),
    ENTRY(PE),
    ENTRY(MACHO),
    ENTRY(OAT),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }

  return "UNKNOWN";
}
}
