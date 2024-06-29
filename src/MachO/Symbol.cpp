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
#ifdef __unix__
  #include <cxxabi.h>
#endif

#include "spdlog/fmt/fmt.h"

#include "LIEF/Visitor.hpp"

#include "LIEF/MachO/Symbol.hpp"
#include "MachO/Structures.hpp"

#include "frozen.hpp"

namespace LIEF {
namespace MachO {

Symbol& Symbol::operator=(Symbol other) {
  swap(other);
  return *this;
}

Symbol::Symbol(const Symbol& other) :
  LIEF::Symbol{other},
  type_{other.type_},
  numberof_sections_{other.numberof_sections_},
  description_{other.description_},
  origin_{other.origin_}
{}


Symbol::Symbol(const details::nlist_32& cmd) :
  type_{cmd.n_type},
  numberof_sections_{cmd.n_sect},
  description_{static_cast<uint16_t>(cmd.n_desc)},
  origin_{ORIGIN::LC_SYMTAB}
{
  value_ = cmd.n_value;
}

Symbol::Symbol(const details::nlist_64& cmd) :
  type_{cmd.n_type},
  numberof_sections_{cmd.n_sect},
  description_{cmd.n_desc},
  origin_{ORIGIN::LC_SYMTAB}
{
  value_ = cmd.n_value;
}


void Symbol::swap(Symbol& other) noexcept {
  LIEF::Symbol::swap(other);

  std::swap(type_,              other.type_);
  std::swap(numberof_sections_, other.numberof_sections_);
  std::swap(description_,       other.description_);
  std::swap(binding_info_,      other.binding_info_);
  std::swap(export_info_,       other.export_info_);
  std::swap(origin_,            other.origin_);
}

std::string Symbol::demangled_name() const {
#if defined(__unix__)
  int status;
  const std::string& name = this->name().c_str();
  char* demangled_name = abi::__cxa_demangle(name.c_str(), 0, 0, &status);

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

void Symbol::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

const Symbol& Symbol::indirect_abs() {
  static const Symbol abs(CATEGORY::INDIRECT_ABS);
  return abs;
}

const Symbol& Symbol::indirect_local() {
  static const Symbol local(CATEGORY::INDIRECT_LOCAL);
  return local;
}


std::ostream& operator<<(std::ostream& os, const Symbol& symbol) {
  //if ((symbol.type_ & MACHO_SYMBOL_TYPES::N_TYPE) == MACHO_SYMBOL_TYPES::N_TYPE) {
  //  type = to_string(
  //      static_cast<N_LIST_TYPES>(symbol.type_ & MACHO_SYMBOL_TYPES::N_TYPE));
  //} else if((symbol.type_ & MACHO_SYMBOL_TYPES::N_STAB) > 0) {
  //  type = to_string(MACHO_SYMBOL_TYPES::N_STAB);
  //} else if((symbol.type_ & MACHO_SYMBOL_TYPES::N_PEXT) == MACHO_SYMBOL_TYPES::N_PEXT) {
  //  type = to_string(MACHO_SYMBOL_TYPES::N_PEXT);
  //}  else if((symbol.type_ & MACHO_SYMBOL_TYPES::N_EXT) == MACHO_SYMBOL_TYPES::N_EXT) {
  //  type = to_string(MACHO_SYMBOL_TYPES::N_EXT);
  //}

  os << fmt::format(
    "name={}, type={}, desc={}, value={}",
    symbol.name(), symbol.raw_type(), symbol.description(), symbol.value()
  ) << '\n';
  return os;
}

const char* to_string(Symbol::ORIGIN e) {
  #define ENTRY(X) std::pair(Symbol::ORIGIN::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNKNOWN),
    ENTRY(DYLD_EXPORT),
    ENTRY(DYLD_BIND),
    ENTRY(LC_SYMTAB),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

const char* to_string(Symbol::CATEGORY e) {
  #define ENTRY(X) std::pair(Symbol::CATEGORY::X, #X)
  STRING_MAP enums2str {
    ENTRY(NONE),
    ENTRY(LOCAL),
    ENTRY(EXTERNAL),
    ENTRY(UNDEFINED),
    ENTRY(INDIRECT_ABS),
    ENTRY(INDIRECT_LOCAL),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

const char* to_string(Symbol::TYPE e) {
  #define ENTRY(X) std::pair(Symbol::TYPE::X, #X)
  STRING_MAP enums2str {
    ENTRY(UNDEFINED),
    ENTRY(ABSOLUTE_SYM),
    ENTRY(SECTION),
    ENTRY(UNDEFINED),
    ENTRY(PREBOUND),
    ENTRY(INDIRECT),
  };
  #undef ENTRY

  if (auto it = enums2str.find(e); it != enums2str.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

} // namespace MachO
} // namespace LIEF
