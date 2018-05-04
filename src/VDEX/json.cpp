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

#include "LIEF/VDEX/json.hpp"
#include "LIEF/DEX/json.hpp"

#include "LIEF/VDEX.hpp"
namespace LIEF {
namespace VDEX {


json to_json(const Object& v) {
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
}


std::string to_json_str(const Object& v) {
  return VDEX::to_json(v).dump();
}


void JsonVisitor::visit(const File& file) {
  JsonVisitor vheader;
  vheader(file.header());

  std::vector<json> dexfiles;
  for (const DEX::File& dexfile : file.dex_files()) {
    dexfiles.emplace_back(DEX::to_json(dexfile));
  }

  this->node_["header"]    = vheader.get();
  this->node_["dex_files"] = dexfiles;
}

void JsonVisitor::visit(const Header& header) {
  this->node_["magic"]                = header.magic();
  this->node_["version"]              = header.version();
  this->node_["nb_dex_files"]         = header.nb_dex_files();
  this->node_["dex_size"]             = header.dex_size();
  this->node_["verifier_deps_size"]   = header.verifier_deps_size();
  this->node_["quickening_info_size"] = header.quickening_info_size();
}

} // namespace VDEX
} // namespace LIEF

#endif // LIEF_JSON_SUPPORT
