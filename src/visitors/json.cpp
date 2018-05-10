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
#include "LIEF/Abstract.hpp"
#include "LIEF/visitors/json.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

#if defined(LIEF_PE_SUPPORT)
#include "LIEF/PE/json.hpp"
#endif

#if defined(LIEF_ELF_SUPPORT)
#include "LIEF/ELF/json.hpp"
#endif

#if defined(LIEF_MACHO_SUPPORT)
#include "LIEF/MachO/json.hpp"
#endif

#if defined(LIEF_OAT_SUPPORT)
#include "LIEF/OAT/json.hpp"
#endif

#if defined(LIEF_ART_SUPPORT)
#include "LIEF/ART/json.hpp"
#endif

#if defined(LIEF_DEX_SUPPORT)
#include "LIEF/DEX/json.hpp"
#endif

#if defined(LIEF_VDEX_SUPPORT)
#include "LIEF/VDEX/json.hpp"
#endif

#include "LIEF/config.h"

namespace LIEF {

json to_json(const Object& v) {
  json node;
#if defined(LIEF_PE_SUPPORT)
  PE::JsonVisitor pe_visitor;
  pe_visitor(v);
  const json& pejson = pe_visitor.get();
  if (pejson.type() != json::value_t::null) {
    node.update(std::move(pejson));
  }
#endif

#if defined(LIEF_ELF_SUPPORT)
  ELF::JsonVisitor elf_visitor;
  elf_visitor(v);
  const json& elfjson = elf_visitor.get();
  if (elfjson.type() != json::value_t::null) {
    node.update(std::move(elfjson));
  }
#endif

#if defined(LIEF_MACHO_SUPPORT)
  MachO::JsonVisitor macho_visitor;
  macho_visitor(v);
  const json& machojson = macho_visitor.get();
  if (machojson.type() != json::value_t::null) {
    node.update(std::move(machojson));
  }
#endif


#if defined(LIEF_OAT_SUPPORT)
  OAT::JsonVisitor oat_visitor;
  oat_visitor(v);
  const json& oatjson = oat_visitor.get();
  if (oatjson.type() != json::value_t::null) {
    node.update(std::move(oatjson));
  }
#endif


#if defined(LIEF_ART_SUPPORT)
  ART::JsonVisitor art_visitor;
  art_visitor(v);
  const json& artjson = art_visitor.get();
  if (artjson.type() != json::value_t::null) {
    node.update(std::move(artjson));
  }
#endif

#if defined(LIEF_DEX_SUPPORT)
  DEX::JsonVisitor dex_visitor;
  dex_visitor(v);
  const json& dexjson = dex_visitor.get();
  if (dexjson.type() != json::value_t::null) {
    node.update(std::move(dexjson));
  }
#endif


#if defined(LIEF_VDEX_SUPPORT)
  VDEX::JsonVisitor vdex_visitor;
  vdex_visitor(v);
  const json& vdexjson = vdex_visitor.get();
  if (vdexjson.type() != json::value_t::null) {
    node.update(std::move(vdexjson));
  }
#endif


  return node;
}

std::string to_json_str(const Object& v) {
  return to_json(v).dump();
}

JsonVisitor::JsonVisitor(void) :
  node_{}
{}

JsonVisitor::JsonVisitor(const json& node) :
  node_{node}
{}

JsonVisitor::JsonVisitor(const JsonVisitor&)            = default;
JsonVisitor& JsonVisitor::operator=(const JsonVisitor&) = default;

const json& JsonVisitor::get(void) const {
  return this->node_;
}

}

