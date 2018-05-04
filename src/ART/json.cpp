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

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/ART/json.hpp"

#include "LIEF/ART.hpp"
#include "LIEF/ART/EnumToString.hpp"
namespace LIEF {
namespace ART {


json to_json(const Object& v) {
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
}


std::string to_json_str(const Object& v) {
  return ART::to_json(v).dump();
}


void JsonVisitor::visit(const File& file) {
  JsonVisitor header_visitor;
  header_visitor(file.header());
  this->node_["header"]                      = header_visitor.get();
}

void JsonVisitor::visit(const Header& header) {
  this->node_["magic"]            = header.magic();
  this->node_["version"]          = header.version();
  this->node_["image_begin"]      = header.image_begin();
  this->node_["image_size"]       = header.image_size();
  this->node_["oat_checksum"]     = header.oat_checksum();
  this->node_["oat_file_begin"]   = header.oat_file_begin();
  this->node_["oat_file_end"]     = header.oat_file_end();
  this->node_["oat_data_begin"]   = header.oat_data_begin();
  this->node_["oat_data_end"]     = header.oat_data_end();
  this->node_["patch_delta"]      = header.patch_delta();
  this->node_["image_roots"]      = header.image_roots();
  this->node_["pointer_size"]     = header.pointer_size();
  this->node_["compile_pic"]      = header.compile_pic();
  this->node_["nb_sections"]      = header.nb_sections();
  this->node_["nb_methods"]       = header.nb_methods();
  this->node_["boot_image_begin"] = header.boot_image_begin();
  this->node_["boot_image_size"]  = header.boot_image_size();
  this->node_["boot_oat_begin"]   = header.boot_oat_begin();
  this->node_["boot_oat_size"]    = header.boot_oat_size();
  this->node_["storage_mode"]     = to_string(header.storage_mode());
  this->node_["data_size"]        = header.data_size();
}

} // namespace ART
} // namespace LIEF

#endif // LIEF_JSON_SUPPORT
