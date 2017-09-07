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
#include "LIEF/Abstract/Abstract.hpp"
#include "LIEF/visitors/json.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

#include "LIEF/config.h"

#ifdef LIEF_JSON_SUPPORT

namespace LIEF {

JsonVisitor::JsonVisitor(void) :
  node_{}
{}

JsonVisitor::JsonVisitor(const json& node) :
  node_{node}
{}

JsonVisitor::JsonVisitor(const JsonVisitor&)            = default;
JsonVisitor& JsonVisitor::operator=(const JsonVisitor&) = default;

void JsonVisitor::visit(const Binary& binary) {
  JsonVisitor header_visitor;
  header_visitor(binary.header());
  std::vector<json> sections_json, symbols_json;

  for (const Section& section : binary.sections()) {
    JsonVisitor section_visitor;
    section_visitor(section);
    sections_json.emplace_back(section_visitor.get());
  }


  for (const Symbol& symbol : binary.symbols()) {
    JsonVisitor visitor;
    visitor(symbol);
    symbols_json.emplace_back(visitor.get());
  }


  this->node_["name"]               = binary.name();
  this->node_["entrypoint"]         = binary.entrypoint();
  this->node_["format"]             = to_string(binary.format());
  this->node_["original_size"]      = binary.original_size();
  this->node_["exported_functions"] = binary.exported_functions();
  this->node_["imported_libraries"] = binary.imported_libraries();
  this->node_["imported_functions"] = binary.imported_functions();
  this->node_["header"]             = header_visitor.get();
  this->node_["sections"]           = sections_json;
  this->node_["symbols"]            = symbols_json;
}


void JsonVisitor::visit(const Header& header) {
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


void JsonVisitor::visit(const Section& section) {
  this->node_["name"]            = section.name();
  this->node_["size"]            = section.size();
  this->node_["offset"]          = section.offset();
  this->node_["virtual_address"] = section.virtual_address();
}


void JsonVisitor::visit(const Symbol& symbol) {
  this->node_["name"] = symbol.name();
}


const json& JsonVisitor::get(void) const {
  return this->node_;
}

}

#endif // LIEF_JSON_SUPPORT
