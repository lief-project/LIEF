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

#ifdef __unix__
  #include <cxxabi.h>
#endif

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

Symbol::~Symbol() = default;

Symbol::Symbol() = default;

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
  origin_{SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB}
{
  value_ = cmd.n_value;
}

Symbol::Symbol(const details::nlist_64& cmd) :
  type_{cmd.n_type},
  numberof_sections_{cmd.n_sect},
  description_{cmd.n_desc},
  origin_{SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB}
{
  value_ = cmd.n_value;
}


Symbol::Symbol(CATEGORY cat) :
  category_{cat}
{}

void Symbol::swap(Symbol& other) {
  LIEF::Symbol::swap(other);

  std::swap(type_,              other.type_);
  std::swap(numberof_sections_, other.numberof_sections_);
  std::swap(description_,       other.description_);
  std::swap(binding_info_,      other.binding_info_);
  std::swap(export_info_,       other.export_info_);
  std::swap(origin_,            other.origin_);
}

uint8_t Symbol::type() const {
  return type_;
}

uint8_t  Symbol::numberof_sections() const {
  return numberof_sections_;
}

uint16_t Symbol::description() const {
  return description_;
}

SYMBOL_ORIGINS Symbol::origin() const {
  return origin_;
}

void Symbol::type(uint8_t type) {
  type_ = type;
}

void Symbol::numberof_sections(uint8_t nbsections) {
  numberof_sections_ = nbsections;
}

void Symbol::description(uint16_t desc) {
  description_ = desc;
}

bool Symbol::is_external() const {
  static constexpr size_t N_TYPE = 0x0e;
  return static_cast<N_LIST_TYPES>(type_ & N_TYPE) == N_LIST_TYPES::N_UNDF;
    //(type_ & MACHO_SYMBOL_TYPES::N_EXT) == MACHO_SYMBOL_TYPES::N_EXT;
    //(type_ & MACHO_SYMBOL_TYPES::N_PEXT) == 0;
}


bool Symbol::has_export_info() const {
  return export_info_ != nullptr;
}

const ExportInfo* Symbol::export_info() const {
  return export_info_;
}

ExportInfo* Symbol::export_info() {
  return const_cast<ExportInfo*>(static_cast<const Symbol*>(this)->export_info());
}

bool Symbol::has_binding_info() const {
  return binding_info_ != nullptr;
}

const BindingInfo* Symbol::binding_info() const {
  return binding_info_;
}

BindingInfo* Symbol::binding_info() {
  return const_cast<BindingInfo*>(static_cast<const Symbol*>(this)->binding_info());
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


const Symbol& Symbol::indirect_abs() {
  static Symbol abs(CATEGORY::INDIRECT_ABS);
  return abs;
}

const Symbol& Symbol::indirect_local() {
  static Symbol local(CATEGORY::INDIRECT_LOCAL);
  return local;
}


std::ostream& operator<<(std::ostream& os, const Symbol& symbol) {
  std::string type;

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



  os << std::hex;
  os << std::left;
  os << std::setw(30) << symbol.name()
     << std::setw(10) << type
     << std::setw(10) << symbol.description()
     << std::setw(20) << symbol.value();
  return os;

}
} // namespace MachO
} // namespace LIEF
