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

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {

Symbol::Symbol(void) = default;
Symbol& Symbol::operator=(const Symbol&) = default;
Symbol::Symbol(const Symbol&) = default;
Symbol::~Symbol(void) = default;

Symbol::Symbol(const nlist_32 *cmd) :
  type_{cmd->n_type},
  numberof_sections_{cmd->n_sect},
  description_{static_cast<uint16_t>(cmd->n_desc)},
  value_{cmd->n_value}
{}

Symbol::Symbol(const nlist_64 *cmd) :
  type_{cmd->n_type},
  numberof_sections_{cmd->n_sect},
  description_{cmd->n_desc},
  value_{cmd->n_value}
{}

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
  return (this->type_ & SYMBOL_TYPES::N_TYPE) == N_LIST_TYPES::N_UNDF;
    //(this->type_ & SYMBOL_TYPES::N_EXT) == SYMBOL_TYPES::N_EXT;
    //(this->type_ & SYMBOL_TYPES::N_PEXT) == 0;
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

  LIEF::Symbol::accept(visitor);

  visitor.visit(this->type());
  visitor.visit(this->numberof_sections());
  visitor.visit(this->description());
  visitor.visit(this->value());
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

  if ((symbol.type_ & SYMBOL_TYPES::N_TYPE) == SYMBOL_TYPES::N_TYPE) {
    type = to_string(
        static_cast<N_LIST_TYPES>(symbol.type_ & SYMBOL_TYPES::N_TYPE));
  } else if((symbol.type_ & SYMBOL_TYPES::N_STAB) > 0) {
    type = to_string(SYMBOL_TYPES::N_STAB);
  } else if((symbol.type_ & SYMBOL_TYPES::N_PEXT) == SYMBOL_TYPES::N_PEXT) {
    type = to_string(SYMBOL_TYPES::N_PEXT);
  }  else if((symbol.type_ & SYMBOL_TYPES::N_EXT) == SYMBOL_TYPES::N_EXT) {
    type = to_string(SYMBOL_TYPES::N_EXT);
  }



  os << std::hex;
  os << std::left;
  os << std::setw(30) << symbol.name_
     << std::setw(10) << type
     << std::setw(10) << symbol.description_
     << std::setw(20) << symbol.value_;
  return os;

}
} // namespace MachO
} // namespace LIEF
