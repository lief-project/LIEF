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
#include "LIEF/Abstract/json.hpp"
#include "LIEF/Abstract.hpp"
#include "LIEF/ELF.hpp"
#include "LIEF/PE.hpp"
#include "LIEF/MachO.hpp"
#include "Object.tcc"
#include "LIEF/config.h"

namespace LIEF {

json to_json_from_abstract(const Object& v) {
  AbstractJsonVisitor visitor;

#if defined(LIEF_ELF_SUPPORT)
  if (v.is<LIEF::ELF::Binary>()) {
    visitor.visit(*v.as<LIEF::Binary>());
  }
  else if (v.is<LIEF::ELF::Section>()) {
    visitor.visit(*v.as<LIEF::Section>());
  }
  else if (v.is<LIEF::ELF::Relocation>()) {
    visitor.visit(*v.as<LIEF::Relocation>());
  }
  else if (v.is<LIEF::ELF::Symbol>()) {
    visitor.visit(*v.as<LIEF::Symbol>());
  } else {
    //TODO: show error
  }
#endif

#if defined(LIEF_PE_SUPPORT)
  if (v.is<LIEF::PE::Binary>()) {
    visitor.visit(*v.as<LIEF::Binary>());
  }
  else if (v.is<LIEF::PE::Section>()) {
    visitor.visit(*v.as<LIEF::Section>());
  }
  else if (v.is<LIEF::PE::Relocation>()) {
    visitor.visit(*v.as<LIEF::Relocation>());
  }
  else if (v.is<LIEF::PE::Symbol>()) {
    visitor.visit(*v.as<LIEF::Symbol>());
  } else {
    //TODO: show error
  }
#endif

#if defined(LIEF_MACHO_SUPPORT)
  if (v.is<LIEF::MachO::Binary>()) {
    visitor.visit(*v.as<LIEF::Binary>());
  }
  else if (v.is<LIEF::MachO::Section>()) {
    visitor.visit(*v.as<LIEF::Section>());
  }
  else if (v.is<LIEF::MachO::Relocation>()) {
    visitor.visit(*v.as<LIEF::Relocation>());
  }
  else if (v.is<LIEF::MachO::Symbol>()) {
    visitor.visit(*v.as<LIEF::Symbol>());
  } else {
    //TODO: show error
  }
#endif

  return visitor.get();
}


std::string to_json_str_from_abstract(const Object& v) {
  return to_json(v).dump();
}


void AbstractJsonVisitor::visit(const Binary& binary) {
  AbstractJsonVisitor header_visitor;
  header_visitor(binary.header());

  // Sections
  std::vector<json> sections;
  for (const Section& section : binary.sections()) {
    AbstractJsonVisitor visitor;
    visitor.visit(section);
    sections.emplace_back(visitor.get());
  }

  std::vector<json> symbols;
  for (const Symbol& sym : binary.symbols()) {
    AbstractJsonVisitor visitor;
    visitor.visit(sym);
    symbols.emplace_back(visitor.get());
  }

  std::vector<json> relocations;
  for (const Relocation& relocation : binary.relocations()) {
    AbstractJsonVisitor visitor;
    visitor.visit(relocation);
    relocations.emplace_back(visitor.get());
  }
  this->node_["name"]               = binary.name();
  this->node_["entrypoint"]         = binary.entrypoint();
  this->node_["format"]             = to_string(binary.format());
  this->node_["original_size"]      = binary.original_size();
  this->node_["exported_functions"] = binary.exported_functions();
  this->node_["imported_libraries"] = binary.imported_libraries();
  this->node_["imported_functions"] = binary.imported_functions();
  this->node_["header"]             = header_visitor.get();
  this->node_["sections"]           = sections;
  this->node_["symbols"]            = symbols;
  this->node_["relocations"]        = relocations;
}


void AbstractJsonVisitor::visit(const Header& header) {
  std::vector<std::string> modes;
  modes.reserve(header.modes().size());
  for (MODES m : header.modes()) {
    modes.push_back(to_string(m));
  }
  this->node_["architecture"] = to_string(header.architecture());
  this->node_["object_type"]  = to_string(header.object_type());
  this->node_["entrypoint"]   = header.entrypoint();
  this->node_["endianness"]   = to_string(header.endianness());
}

void AbstractJsonVisitor::visit(const Section& section) {
  this->node_["name"]            = section.name();
  this->node_["size"]            = section.size();
  this->node_["offset"]          = section.offset();
  this->node_["virtual_address"] = section.virtual_address();
}

void AbstractJsonVisitor::visit(const Symbol& symbol) {
  this->node_["name"] = symbol.name();
}

void AbstractJsonVisitor::visit(const Relocation& relocation) {
  this->node_["address"] = relocation.address();
  this->node_["size"]    = relocation.size();
}




} // namespace LIEF
