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

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

Symbol::~Symbol(void) = default;

Symbol::Symbol(void) :
  type_{0},
  numberof_sections_{0},
  description_{0},
  value_{0},
  binding_info_{nullptr},
  export_info_{nullptr},
  origin_{SYMBOL_ORIGINS::SYM_ORIGIN_UNKNOWN}
{}

Symbol& Symbol::operator=(Symbol other) {
  this->swap(other);
  return *this;
}

Symbol::Symbol(const Symbol& other) :
  LIEF::Symbol{other},
  type_{other.type_},
  numberof_sections_{other.numberof_sections_},
  description_{other.description_},
  value_{other.value_},
  binding_info_{nullptr},
  export_info_{nullptr},
  origin_{other.origin_}
{}


Symbol::Symbol(const nlist_32 *cmd) :
  type_{cmd->n_type},
  numberof_sections_{cmd->n_sect},
  description_{static_cast<uint16_t>(cmd->n_desc)},
  value_{cmd->n_value},
  binding_info_{nullptr},
  export_info_{nullptr},
  origin_{SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB}
{}

Symbol::Symbol(const nlist_64 *cmd) :
  type_{cmd->n_type},
  numberof_sections_{cmd->n_sect},
  description_{cmd->n_desc},
  value_{cmd->n_value},
  binding_info_{nullptr},
  export_info_{nullptr},
  origin_{SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB}
{}


void Symbol::swap(Symbol& other) {
  std::swap(this->name_,              other.name_);

  std::swap(this->type_,              other.type_);
  std::swap(this->numberof_sections_, other.numberof_sections_);
  std::swap(this->description_,       other.description_);
  std::swap(this->value_,             other.value_);
  std::swap(this->binding_info_,      other.binding_info_);
  std::swap(this->export_info_,       other.export_info_);
  std::swap(this->origin_,            other.origin_);
}

uint8_t Symbol::type(void) const {
  return this->type_;
}

uint8_t  Symbol::numberof_sections(void) const {
  return this->numberof_sections_;
}

uint16_t Symbol::description(void) const {
  return this->description_;
}

uint64_t Symbol::value(void) const {
  return this->value_;
}

SYMBOL_ORIGINS Symbol::origin(void) const {
  return this->origin_;
}

void Symbol::type(uint8_t type) {
  this->type_ = type;
}

void Symbol::numberof_sections(uint8_t nbsections) {
  this->numberof_sections_ = nbsections;
}

void Symbol::description(uint16_t desc) {
  this->description_ = desc;
}

void Symbol::value(uint64_t value) {
  this->value_ = value;
}

bool Symbol::is_external(void) const {
  static constexpr size_t N_TYPE = 0x0e;
  return static_cast<N_LIST_TYPES>(this->type_ & N_TYPE) == N_LIST_TYPES::N_UNDF;
    //(this->type_ & MACHO_SYMBOL_TYPES::N_EXT) == MACHO_SYMBOL_TYPES::N_EXT;
    //(this->type_ & MACHO_SYMBOL_TYPES::N_PEXT) == 0;
}


bool Symbol::has_export_info(void) const {
  return this->export_info_ != nullptr;
}

const ExportInfo& Symbol::export_info(void) const {
  if (not this->has_export_info()) {
    throw not_found("'" + this->name() + "' hasn't export info");
  }
  return *this->export_info_;
}

ExportInfo& Symbol::export_info(void) {
  return const_cast<ExportInfo&>(static_cast<const Symbol*>(this)->export_info());
}

bool Symbol::has_binding_info(void) const {
  return this->binding_info_ != nullptr;
}
const BindingInfo& Symbol::binding_info(void) const {
  if (not this->has_binding_info()) {
    throw not_found("'" + this->name() + "' hasn't binding info");
  }
  return *this->binding_info_;
}

BindingInfo& Symbol::binding_info(void) {
  return const_cast<BindingInfo&>(static_cast<const Symbol*>(this)->binding_info());
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
