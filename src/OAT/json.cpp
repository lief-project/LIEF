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
#include "LIEF/OAT/EnumToString.hpp"

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/OAT/json.hpp"

#include "LIEF/OAT.hpp"
namespace LIEF {
namespace OAT {


json to_json(const Object& v) {
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
}

std::string to_json_str(const Object& v) {
  return OAT::to_json(v).dump();
}


void JsonVisitor::visit(const Binary& binary) {
  JsonVisitor header_visitor;
  header_visitor(binary.header());

  std::vector<json> dex_files;
  for (const DexFile& file : binary.oat_dex_files()) {
    JsonVisitor dexfile_visitor;
    dexfile_visitor.visit(file);
    dex_files.emplace_back(dexfile_visitor.get());
  }

  std::vector<json> classes;
  for (const Class& cls : binary.classes()) {
    JsonVisitor cls_visitor;
    cls_visitor.visit(cls);
    classes.emplace_back(cls_visitor.get());
  }

  std::vector<json> methods;
  for (const Method& mtd : binary.methods()) {
    JsonVisitor method_visitor;
    method_visitor.visit(mtd);
    methods.emplace_back(method_visitor.get());
  }

  this->node_["header"]    = header_visitor.get();
  this->node_["dex_files"] = dex_files;
  this->node_["classes"]   = classes;
  this->node_["methods"]   = methods;
}

void JsonVisitor::visit(const Header& header) {
  this->node_["magic"]                                = header.magic();
  this->node_["version"]                              = header.version();
  this->node_["checksum"]                             = header.checksum();
  this->node_["instruction_set"]                      = to_string(header.instruction_set());
  this->node_["nb_dex_files"]                         = header.nb_dex_files();
  this->node_["oat_dex_files_offset"]                 = header.oat_dex_files_offset();
  this->node_["executable_offset"]                    = header.executable_offset();
  this->node_["i2i_bridge_offset"]                    = header.i2i_bridge_offset();
  this->node_["i2c_code_bridge_offset"]               = header.i2c_code_bridge_offset();
  this->node_["jni_dlsym_lookup_offset"]              = header.jni_dlsym_lookup_offset();

  this->node_["quick_generic_jni_trampoline_offset"]  = header.quick_generic_jni_trampoline_offset();
  this->node_["quick_imt_conflict_trampoline_offset"] = header.quick_imt_conflict_trampoline_offset();
  this->node_["quick_resolution_trampoline_offset"]   = header.quick_resolution_trampoline_offset();
  this->node_["quick_to_interpreter_bridge_offset"]   = header.quick_to_interpreter_bridge_offset();

  this->node_["image_patch_delta"]                    = header.image_patch_delta();
  this->node_["image_file_location_oat_checksum"]     = header.image_file_location_oat_checksum();
  this->node_["image_file_location_oat_data_begin"]   = header.image_file_location_oat_data_begin();
  this->node_["key_value_size"]                       = header.key_value_size();

  this->node_["keys_values"] = std::vector<json>{};
  for (auto&& key_val : header.key_values()) {
    std::string k = to_string(key_val.first);
    this->node_["keys_values"].emplace_back(std::make_pair(k, key_val.second));
  }
}

void JsonVisitor::visit(const DexFile& dex_file) {
  this->node_["location"]            = dex_file.location();
  this->node_["checksum"]            = dex_file.checksum();
  this->node_["dex_offset"]          = dex_file.dex_offset();
  this->node_["classes_offsets"]     = dex_file.classes_offsets();
  this->node_["lookup_table_offset"] = dex_file.lookup_table_offset();
  this->node_["lookup_table_offset"] = dex_file.lookup_table_offset();
}

void JsonVisitor::visit(const Class& cls) {
  this->node_["status"]    = to_string(cls.status());
  this->node_["type"]      = to_string(cls.type());
  this->node_["fullname"]  = cls.fullname();
  this->node_["index"]     = cls.index();
}

void JsonVisitor::visit(const Method& method) {
  this->node_["name"]                 = method.name();
  this->node_["is_compiled"]          = method.is_compiled();
  this->node_["is_dex2dex_optimized"] = method.is_dex2dex_optimized();
}



} // namespace OAT
} // namespace LIEF

#endif // LIEF_JSON_SUPPORT
