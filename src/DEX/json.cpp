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

#include "LIEF/config.h"
#include "LIEF/DEX/EnumToString.hpp"

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/DEX/json.hpp"

#include "LIEF/DEX.hpp"
namespace LIEF {
namespace DEX {


json to_json(const Object& v) {
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
}


std::string to_json_str(const Object& v) {
  return DEX::to_json(v).dump();
}


void JsonVisitor::visit(const File& file) {
  JsonVisitor header_visitor;
  header_visitor(file.header());

  JsonVisitor map_item_visitor;
  map_item_visitor(file.map());

  // Classes
  std::vector<json> classes;
  for (const Class& cls : file.classes()) {
    JsonVisitor clsvisitor;
    clsvisitor(cls);
    classes.emplace_back(clsvisitor.get());
  }

  this->node_["header"]  = header_visitor.get();
  this->node_["classes"] = classes;
  this->node_["map"]     = map_item_visitor.get();
}

void JsonVisitor::visit(const Header& header) {
  this->node_["magic"]       = header.magic();
  this->node_["checksum"]    = header.checksum();
  this->node_["signature"]   = header.signature();
  this->node_["file_size"]   = header.file_size();
  this->node_["header_size"] = header.header_size();
  this->node_["endian_tag"]  = header.endian_tag();
  this->node_["map"]         = header.map();
  this->node_["strings"]     = header.strings();
  this->node_["link"]        = header.link();
  this->node_["types"]       = header.types();
  this->node_["prototypes"]  = header.prototypes();
  this->node_["fields"]      = header.fields();
  this->node_["methods"]     = header.methods();
  this->node_["classes"]     = header.classes();
  this->node_["data"]        = header.data();
}

void JsonVisitor::visit(const CodeInfo& code_info) {
}

void JsonVisitor::visit(const Class& cls) {
  std::vector<json> flags;
  for (ACCESS_FLAGS f : cls.access_flags()) {
    flags.emplace_back(to_string(f));
  }

  std::vector<json> methods;
  for (const Method& m : cls.methods()) {
    JsonVisitor mv;
    mv(m);
    methods.emplace_back(mv.get());
  }
  this->node_["fullname"]         = cls.fullname();
  this->node_["source_filename"]  = cls.source_filename();
  this->node_["access_flags"]     = flags;
  this->node_["index"]            = cls.index();
  this->node_["methods"]          = methods;

  if (cls.has_parent()) {
    this->node_["parent"] = cls.parent().fullname();
  }
}

void JsonVisitor::visit(const Method& method) {
  std::vector<json> flags;
  for (ACCESS_FLAGS f : method.access_flags()) {
    flags.emplace_back(to_string(f));
  }

  JsonVisitor proto_visitor;
  proto_visitor(method.prototype());

  this->node_["name"]         = method.name();
  this->node_["code_offset"]  = method.code_offset();
  this->node_["index"]        = method.index();
  this->node_["is_virtual"]   = method.is_virtual();
  this->node_["prototype"]    = proto_visitor.get();
  this->node_["access_flags"] = flags;
}

void JsonVisitor::visit(const Type& type) {

  this->node_["type"] = to_string(type.type());
  switch(type.type()) {
    case Type::TYPES::CLASS:
      {
        this->node_["value"] = type.cls().fullname();
        break;
      }

    case Type::TYPES::PRIMITIVE:
      {
        this->node_["value"] = Type::pretty_name(type.primitive());
        break;
      }

    case Type::TYPES::ARRAY:
      {
        const Type& uderlying_t = type.underlying_array_type();
        this->node_["dim"] = type.dim();

        if (uderlying_t.type() == Type::TYPES::CLASS) {
          this->node_["value"] = uderlying_t.cls().fullname();
          break;
        }

        if (uderlying_t.type() == Type::TYPES::PRIMITIVE) {
          this->node_["value"] = Type::pretty_name(type.primitive());
          break;
        }
        break;
      }
    default:
      {}
  }
}

void JsonVisitor::visit(const Prototype& type) {
  JsonVisitor rtype_visitor;
  rtype_visitor(type.return_type());

  std::vector<json> params;
  for (const Type& t : type.parameters_type()) {
    JsonVisitor pvisitor;
    pvisitor(t);
    params.emplace_back(pvisitor.get());

  }

  this->node_["return_type"] = rtype_visitor.get();
  this->node_["parameters"]  = params;
}

void JsonVisitor::visit(const MapItem& item) {
  this->node_["offset"] = item.offset();
  this->node_["size"]   = item.size();
  this->node_["type"]   = to_string(item.type());

}

void JsonVisitor::visit(const MapList& list) {
  std::vector<json> items;
  for (const MapItem& i : list.items()) {
    JsonVisitor itemvisitor;
    itemvisitor(i);
    items.emplace_back(itemvisitor.get());
  }
  this->node_["map_items"] = items;
}



} // namespace DEX
} // namespace LIEF

#endif // LIEF_JSON_SUPPORT
