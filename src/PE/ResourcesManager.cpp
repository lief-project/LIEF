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
#include <algorithm>
#include <iomanip>
#include <numeric>

#include "rang.hpp"

#include "LIEF/logging++.h"

#include "LIEF/exception.hpp"
#include "LIEF/visitors/Hash.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/ResourceData.hpp"

#include "LIEF/PE/resources/LangCodeItem.hpp"

namespace LIEF {
namespace PE {

ResourcesManager::ResourcesManager(const ResourcesManager&) = default;
ResourcesManager& ResourcesManager::operator=(const ResourcesManager&) = default;
ResourcesManager::~ResourcesManager(void) = default;

ResourcesManager::ResourcesManager(ResourceNode *rsrc) :
  resources_{rsrc}
{}


// Enhancemed API to explore resource tree
// =======================================

ResourceNode& ResourcesManager::get_node_type(RESOURCE_TYPES type) {
  return const_cast<ResourceNode&>(static_cast<const ResourcesManager*>(this)->get_node_type(type));
}

const ResourceNode& ResourcesManager::get_node_type(RESOURCE_TYPES type) const {
  if (not this->has_type(type)) {
    throw not_found(std::string("Can't find the node with type '") + to_string(type) + "'");
  }

  it_childs nodes = this->resources_->childs();
  auto&& it_node = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [type] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == type;
      });

  return *it_node;
}

std::set<RESOURCE_TYPES> ResourcesManager::get_types_available(void) const {
  std::set<RESOURCE_TYPES> types;
  for (const ResourceNode& node : this->resources_->childs()) {
    auto&& it = std::find_if(
        std::begin(resource_types_array),
        std::end(resource_types_array),
        [&node] (RESOURCE_TYPES t) {
          return t == static_cast<RESOURCE_TYPES>(node.id());
        });
    if (it != std::end(resource_types_array)) {
      types.insert(*it);
    }
  }
  return types;

}

std::set<RESOURCE_LANGS> ResourcesManager::get_langs_available(void) const {
  std::set<RESOURCE_LANGS> langs;
  for (const ResourceNode& node_lvl_1 : this->resources_->childs()) {
    for (const ResourceNode& node_lvl_2 : node_lvl_1.childs()) {
      for (const ResourceNode& node_lvl_3 : node_lvl_2.childs()) {

        RESOURCE_LANGS lang = static_cast<RESOURCE_LANGS>(node_lvl_3.id() & 0x3ff);

        auto&& it = std::find_if(
            std::begin(resource_langs_array),
            std::end(resource_langs_array),
            [lang] (RESOURCE_LANGS t) {
              return t == lang;
            });

        if (it != std::end(resource_langs_array)) {
          langs.insert(*it);
        }
      }
    }
  }
  return langs;
}

std::set<RESOURCE_SUBLANGS> ResourcesManager::get_sublangs_available(void) const {
  std::set<RESOURCE_SUBLANGS> sublangs;
  for (const ResourceNode& node_lvl_1 : this->resources_->childs()) {
    for (const ResourceNode& node_lvl_2 : node_lvl_1.childs()) {
      for (const ResourceNode& node_lvl_3 : node_lvl_2.childs()) {

        RESOURCE_SUBLANGS sub_lang = static_cast<RESOURCE_SUBLANGS>(node_lvl_3.id() >> 10);

        auto&& it = std::find_if(
            std::begin(resource_sublangs_array),
            std::end(resource_sublangs_array),
            [sub_lang] (RESOURCE_SUBLANGS t) {
              return t == sub_lang;
            });

        if (it != std::end(resource_sublangs_array)) {
          sublangs.insert(*it);
        }
      }
    }
  }
  return sublangs;
}

bool ResourcesManager::has_type(RESOURCE_TYPES type) const {
  it_childs nodes = this->resources_->childs();
  auto&& it_node = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [type] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == type;
      });

  return it_node != std::end(nodes);
}


// Manifest
// ========

bool ResourcesManager::has_manifest(void) const {
  it_childs nodes = this->resources_->childs();
  auto&& it_manifest = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::MANIFEST;
      });
  return it_manifest != std::end(nodes);

}

std::string ResourcesManager::manifest(void) const {
  if (not this->has_manifest()) {
    throw not_found("No manifest found in the resources");
  }

  it_childs nodes = this->resources_->childs();
  auto&& it_manifest = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::MANIFEST;
      });
  const ResourceData* manifest_node = dynamic_cast<ResourceData*>(&((*it_manifest).childs()[0].childs()[0]));
  const std::vector<uint8_t>& content = manifest_node->content();
  return std::string{std::begin(content), std::end(content)};
}

void ResourcesManager::manifest(const std::string& manifest) {
  if (not this->has_manifest()) {
    //TODO
    //ResourceDirectory* dir1 = new ResourceDirectory{};
    //ResourceDirectory* dir2 = new ResourceDirectory{};
    //ResourceData* data = new ResourceData{};
    throw not_implemented("Not manifest already present");
  }

  it_childs nodes = this->resources_->childs();
  auto&& it_manifest = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::MANIFEST;
      });

  ResourceData* manifest_node = dynamic_cast<ResourceData*>(&((*it_manifest).childs()[0].childs()[0]));
  manifest_node->content({std::begin(manifest), std::end(manifest)});
}


// Resource Version
// ================
bool ResourcesManager::has_version(void) const {
  it_childs nodes = this->resources_->childs();
  auto&& it_version = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::VERSION;
      });
  return it_version != std::end(nodes);
}

ResourceVersion ResourcesManager::version(void) const {
  if (not this->has_version()) {
    throw not_found("Resource version not found");
  }

  it_childs nodes = this->resources_->childs();
  auto&& it_version = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::VERSION;
      });

  const ResourceData* version_node = dynamic_cast<ResourceData*>(&((*it_version).childs()[0].childs()[0]));
  const std::vector<uint8_t>& content = version_node->content();
  VectorStream stream{content};
  ResourceVersion version;

  uint64_t offset = 0;

  // Size of the current "struct"
  const uint16_t length = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
  offset += sizeof(uint16_t);
  VLOG(VDEBUG) << "Lenght of the struct: 0x" << std::hex << length;

  // Size of the fixed file info struct
  const uint16_t value_length = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
  offset += sizeof(uint16_t);
  VLOG(VDEBUG) << "Size of the 'FixedFileInfo' struct" << std::hex << value_length;

  // Type of the data in the version resource
  // 1: Text data
  // 0: Binary data
  const uint16_t type = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
  offset += sizeof(uint16_t);
  version.type_ = type;
  if (type != 0 and type != 1) {
    LOG(WARNING) << "\"type\" of the resource version should be equal to 0 or 1 (" << std::dec << type << ")";
  }


  // Magic key: VS_VERSION_INFO
  std::u16string key = {reinterpret_cast<const char16_t*>(content.data() + offset)};
  if (u16tou8(key) != "VS_VERSION_INFO") {
    LOG(WARNING) << "\"key\" of the resource version should be equal to 'VS_VERSION_INFO' (" << u16tou8(key) << ")";
  }

  version.key_ = key;
  offset += (key.size() + 1) * sizeof(char16_t);
  offset = align(offset, sizeof(uint32_t));

  if (value_length > 0) {
    if (value_length == sizeof(pe_resource_fixed_file_info)) {
      const pe_resource_fixed_file_info* fixed_file_info_header = reinterpret_cast<const pe_resource_fixed_file_info*>(stream.read(offset, sizeof(pe_resource_fixed_file_info)));
      if (fixed_file_info_header->signature != 0xFEEF04BD) {
        LOG(WARNING) << "Bad magic value for the Fixed file info structure";
      } else {
        version.fixed_file_info_ = ResourceFixedFileInfo{fixed_file_info_header};
        version.has_fixed_file_info_ = true;
      }
    } else {
      LOG(WARNING) << "The 'value' member contains an unknown structure";
    }

    offset += value_length * sizeof(uint8_t);
  }
  offset = align(offset, sizeof(uint32_t));


  { // First entry
    VLOG(VDEBUG) << "Parsing first entry";
    const uint16_t struct_file_info_length = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
    uint64_t local_offset = offset;
    VLOG(VDEBUG) << "Length: " << std::hex << struct_file_info_length;
    if (struct_file_info_length > 0) {
      local_offset += sizeof(uint16_t);

      const uint16_t struct_length = *reinterpret_cast<const uint16_t*>(stream.read(local_offset, sizeof(uint16_t)));
      local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Lenght of the struct: 0x" << std::hex << struct_length;

      const uint16_t type = *reinterpret_cast<const uint16_t*>(stream.read(local_offset, sizeof(uint16_t)));
      local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Type of the struct: " << std::dec << type;

      std::u16string key = {reinterpret_cast<const char16_t*>(content.data() + local_offset)};
      VLOG(VDEBUG) << "First entry (key) " << u16tou8(key);
      if (u16tou8(key) == "StringFileInfo") {
        try {
          version.string_file_info_ = this->get_string_file_info(stream, offset);
          version.has_string_file_info_ = true;
        } catch (const LIEF::exception& e) {
          LOG(ERROR) << e.what();
        }
      }

      if (u16tou8(key) == "VarFileInfo") {
        try {
          version.var_file_info_ = this->get_var_file_info(stream, offset);
          version.has_var_file_info_ = true;
        } catch (const LIEF::exception& e) {
          LOG(ERROR) << e.what();
        }
      }
    }
  }


  { // Second entry

    VLOG(VDEBUG) << "Parsing second entry";
    const uint16_t struct_file_info_length = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
    uint64_t local_offset = offset;
    VLOG(VDEBUG) << "Length: " << std::hex << struct_file_info_length;

    if (struct_file_info_length > 0) {
      local_offset += sizeof(uint16_t);

      const uint16_t struct_length = *reinterpret_cast<const uint16_t*>(stream.read(local_offset, sizeof(uint16_t)));
      local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Lenght of the struct: 0x" << std::hex << struct_length;

      const uint16_t type = *reinterpret_cast<const uint16_t*>(stream.read(local_offset, sizeof(uint16_t)));
      local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Type of the struct: " << std::dec << type;

      std::u16string key = {reinterpret_cast<const char16_t*>(content.data() + local_offset)};

      VLOG(VDEBUG) << "Second entry (key) " << u16tou8(key);
      if (u16tou8(key) == "StringFileInfo") {
        try {
          version.string_file_info_ = this->get_string_file_info(stream, offset);
          version.has_string_file_info_ = true;
        } catch (const LIEF::exception& e) {
          LOG(ERROR) << e.what();
        }
      }

      if (u16tou8(key) == "VarFileInfo") {
        try {
          version.var_file_info_ = this->get_var_file_info(stream, offset);
          version.has_var_file_info_ = true;
        } catch (const LIEF::exception& e) {
          LOG(ERROR) << e.what();
        }
      }
    }
  }

  return version;
}


ResourceStringFileInfo ResourcesManager::get_string_file_info(const VectorStream& stream, uint64_t& offset) const {
  VLOG(VDEBUG) << "Getting StringFileInfo object";

  // String File Info
  // ================
  ResourceStringFileInfo string_file_info;
  const uint16_t string_file_info_length = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
  uint64_t str_local_offset = offset;
  if (string_file_info_length > 0) {
    str_local_offset += sizeof(uint16_t);

    const uint16_t value_length = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
    str_local_offset += sizeof(uint16_t);
    VLOG(VDEBUG) << "Value length: " << std::dec << value_length << " (should be 0)";

    const uint16_t type = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
    VLOG(VDEBUG) << "Type: " << std::dec << type;

    str_local_offset += sizeof(uint16_t);
    string_file_info.type_ = type;

    std::u16string key = {reinterpret_cast<const char16_t*>(stream.content().data() + str_local_offset)};
    if (u16tou8(key) != "StringFileInfo") {
      LOG(WARNING) << "\"key\" of the resource version should be equal to 'StringFileInfo' (" << u16tou8(key) << ")";
    }
    string_file_info.key_ = key;

    str_local_offset += (key.size() + 1) * sizeof(char16_t);
    str_local_offset = align(str_local_offset, sizeof(uint32_t));

    // Parse 'StringTable' childs
    // ==========================
    VLOG(VDEBUG) << "Parsing 'StringTable' struct";
    while (str_local_offset < offset + string_file_info_length * sizeof(uint8_t)) {
      LangCodeItem lang_code_item;
      const uint16_t stringtable_length = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));

      // End of the structure including childs
      const uint64_t end_offset = str_local_offset + stringtable_length * sizeof(uint8_t);

      str_local_offset += sizeof(uint16_t);

      const uint16_t stringtable_value_length = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
      str_local_offset += sizeof(uint16_t);

      VLOG(VDEBUG) << "Value length: " << std::dec << stringtable_value_length << " (should be 0)";

      const uint16_t stringtable_type = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
      VLOG(VDEBUG) << "Type: " << std::dec << stringtable_type;
      str_local_offset += sizeof(uint16_t);

      // 1: Text data
      // 0: Binary data
      if (type != 0 and type != 1) {
        LOG(WARNING) << "\"type\" of the StringTable should be equal to 0 or 1 (" << std::dec << type << ")";
      }
      lang_code_item.type_ = type;


      std::u16string key = {reinterpret_cast<const char16_t*>(stream.content().data() + str_local_offset)};
      lang_code_item.key_ = key;
      VLOG(VDEBUG) << "ID: " << u16tou8(key);

      std::string key_str = u16tou8(key);

      if (key.length() != 8) {
        LOG(ERROR) << "Corrupted key (" << u16tou8(key) << key_str << ")";
      } else {
        uint64_t lang_id   = std::stoul(u16tou8(key.substr(0, 4)), 0, 16);
        uint64_t code_page = std::stoul(u16tou8(key.substr(4, 8)), 0, 16);
        VLOG(VDEBUG) << "Lang ID: "   << std::dec << lang_id;
        VLOG(VDEBUG) << "Code page: " << std::hex << code_page;
      }

      str_local_offset += (key.size() + 1) * sizeof(char16_t);
      str_local_offset = align(str_local_offset, sizeof(uint32_t));

      // Parse 'String'
      // ==============
      while (str_local_offset < end_offset) {
        const uint16_t string_length = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
        str_local_offset += sizeof(uint16_t);
        VLOG(VDEBUG) << "Length of the 'string' struct: 0x" << std::hex << string_length;

        const uint16_t string_value_length = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
        str_local_offset += sizeof(uint16_t);
        VLOG(VDEBUG) << "Size of the 'value' member: 0x" << std::hex << string_value_length;

        const uint16_t string_type = *reinterpret_cast<const uint16_t*>(stream.read(str_local_offset, sizeof(uint16_t)));
        str_local_offset += sizeof(uint16_t);
        VLOG(VDEBUG) << "Type of the 'string' struct: " << std::dec << string_type;

        std::u16string key = {reinterpret_cast<const char16_t*>(stream.content().data() + str_local_offset)};
        VLOG(VDEBUG) << "Key: " << u16tou8(key);
        str_local_offset += (key.size() + 1) * sizeof(char16_t);
        str_local_offset = align(str_local_offset, sizeof(uint32_t));

        std::u16string value = {reinterpret_cast<const char16_t*>(stream.content().data() + str_local_offset)};
        VLOG(VDEBUG) << "Value: " << u16tou8(value);
        str_local_offset += (value.size() + 1) * sizeof(char16_t);

        str_local_offset = align(str_local_offset, sizeof(uint32_t));
        lang_code_item.items_.emplace(key, value);
      }
      string_file_info.childs_.push_back(std::move(lang_code_item));
    }
  }
  //offset += string_file_info_length * sizeof(uint8_t);
  offset = str_local_offset;
  return string_file_info;
}


ResourceVarFileInfo ResourcesManager::get_var_file_info(const VectorStream& stream, uint64_t& offset) const {
  VLOG(VDEBUG) << "Getting VarFileInfo object";
  // Var file info
  // =============
  ResourceVarFileInfo var_file_info;
  const uint16_t var_file_info_length = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
  uint64_t var_local_offset = offset;

  if (var_file_info_length > 0) {
    var_local_offset += sizeof(uint16_t);

    const uint16_t value_length = *reinterpret_cast<const uint16_t*>(stream.read(var_local_offset, sizeof(uint16_t)));
    var_local_offset += sizeof(uint16_t);
    VLOG(VDEBUG) << "Value length: " << std::dec << value_length << " (should be 0)";

    const uint16_t type = *reinterpret_cast<const uint16_t*>(stream.read(var_local_offset, sizeof(uint16_t)));
    var_local_offset += sizeof(uint16_t);
    var_file_info.type_ = type;
    VLOG(VDEBUG) << "Type: " << std::dec << type;

    std::u16string key = {reinterpret_cast<const char16_t*>(stream.content().data() + var_local_offset)};
    if (u16tou8(key) != "VarFileInfo") {
      LOG(WARNING) << "\"key\" of the resource version should be equal to 'VarFileInfo' (" << u16tou8(key) << ")";
    }
    var_file_info.key_ = key;

    var_local_offset += (key.size() + 1) * sizeof(char16_t);
    var_local_offset = align(var_local_offset, sizeof(uint32_t));

    // Parse 'Var' childs
    // ==================
    VLOG(VDEBUG) << "Parsing 'Var' childs";
    while (var_local_offset < offset + var_file_info_length * sizeof(uint8_t)) {
      const uint16_t var_length = *reinterpret_cast<const uint16_t*>(stream.read(var_local_offset, sizeof(uint16_t)));
      var_local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Size of the 'Var' struct: 0x" << std::hex << var_length;

      const uint16_t var_value_length = *reinterpret_cast<const uint16_t*>(stream.read(var_local_offset, sizeof(uint16_t)));
      var_local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Size of the 'Value' member: 0x" << std::hex << var_value_length;

      const uint16_t var_type = *reinterpret_cast<const uint16_t*>(stream.read(var_local_offset, sizeof(uint16_t)));
      var_local_offset += sizeof(uint16_t);
      VLOG(VDEBUG) << "Type: " << std::dec << var_type;

      std::u16string key = {reinterpret_cast<const char16_t*>(stream.content().data() + var_local_offset)};
      if (u16tou8(key) != "Translation") {
        LOG(WARNING) << "\"key\" of the var key should be equal to 'Translation' (" << u16tou8(key) << ")";
      }

      var_local_offset += (key.size() + 1) * sizeof(char16_t);
      var_local_offset = align(var_local_offset, sizeof(uint32_t));

      const uint32_t *value_array = reinterpret_cast<const uint32_t*>(stream.read(var_local_offset, var_value_length * sizeof(uint8_t)));
      const size_t nb_items = var_value_length / sizeof(uint32_t);
      for (size_t i = 0; i < nb_items; ++i) {
        VLOG(VDEBUG) << "item[" << std::dec << i << "] = " << std::hex << value_array[i];
        var_file_info.translations_.push_back(value_array[i]);
      }
      var_local_offset += var_value_length;
    }
  }
//  offset += var_file_info_length * sizeof(uint8_t);

  offset = var_local_offset;
  return var_file_info;

}

// Icons
// =====

bool ResourcesManager::has_icons(void) const {

  it_childs nodes = this->resources_->childs();
  auto&& it_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::ICON;
      });


  auto&& it_grp_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::GROUP_ICON;
      });


  if (it_icon == std::end(nodes)) {
    return false;
  }

  if (it_grp_icon == std::end(nodes)) {
    return false;
  }

  return true;

}

std::vector<ResourceIcon> ResourcesManager::icons(void) const {

  it_childs nodes = this->resources_->childs();
  auto&& it_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::ICON;
      });


  auto&& it_grp_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    throw not_found(std::string("Missing '") + to_string(RESOURCE_TYPES::ICON) + "' entry");
  }

  if (it_grp_icon == std::end(nodes)) {
    throw not_found(std::string("Missing '") + to_string(RESOURCE_TYPES::GROUP_ICON) + "' entry");
  }

  std::vector<ResourceIcon> icons;
  for (const ResourceNode& grp_icon_lvl2 : it_grp_icon->childs()) {
    for (const ResourceNode& grp_icon_lvl3 : grp_icon_lvl2.childs()) {
      const ResourceData* icon_group_node = dynamic_cast<const ResourceData*>(&grp_icon_lvl3);
      const std::vector<uint8_t>& icon_group_content = icon_group_node->content();

      const pe_resource_icon_dir* group_icon_header = reinterpret_cast<const pe_resource_icon_dir*>(icon_group_content.data());

      VLOG(VDEBUG) << "Number of icons: " << std::dec << static_cast<uint32_t>(group_icon_header->count);
      VLOG(VDEBUG) << "Type: "            << std::dec << static_cast<uint32_t>(group_icon_header->type);

      // Some checks
      if (group_icon_header->type != 1) {
        throw corrupted("Group icon type should be equal to 1 (" + std::to_string(group_icon_header->type) + ")");
      }

      if ((group_icon_header->count * sizeof(pe_resource_icon_group) + sizeof(pe_resource_icon_dir)) > icon_group_content.size()) {
        throw corrupted("The Number of icons seems corrupted (" + std::to_string(group_icon_header->count) + ")");
      }

      for (size_t i = 0; i < group_icon_header->count; ++i) {
        const pe_resource_icon_group* icon_header = reinterpret_cast<const pe_resource_icon_group*>(
            icon_group_content.data() +
            sizeof(pe_resource_icon_dir) +
            i * sizeof(pe_resource_icon_group));

        const uint32_t id = icon_header->ID;

        ResourceIcon icon{icon_header};
        icon.sublang_ = static_cast<RESOURCE_SUBLANGS>(grp_icon_lvl3.id() >> 10);
        icon.lang_    = static_cast<RESOURCE_LANGS>(grp_icon_lvl3.id() & 0x3fff);
        it_childs sub_nodes_icons = it_icon->childs();

        auto&& it_icon_dir = std::find_if(
            std::begin(sub_nodes_icons),
            std::end(sub_nodes_icons),
            [&id] (const ResourceNode& node) {
              return node.id() == id;
            });

        if (it_icon_dir == std::end(sub_nodes_icons)) {
          LOG(ERROR) << "Unable to find the icon associated with id: " << std::to_string(id);
          continue;
        }
        // TODO: add checks
        const std::vector<uint8_t>& pixels = dynamic_cast<const ResourceData*>(&(it_icon_dir->childs()[0]))->content();
        icon.pixels_ = pixels;

        icons.push_back(icon);
      }
    }
  }

  return icons;
}


void ResourcesManager::add_icon(const ResourceIcon& icon) {
  it_childs nodes = this->resources_->childs();
  auto&& it_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::ICON;
      });


  auto&& it_grp_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    throw not_found(std::string("Missing '") + to_string(RESOURCE_TYPES::ICON) + "' entry");
  }

  if (it_grp_icon == std::end(nodes)) {
    throw not_found(std::string("Missing '") + to_string(RESOURCE_TYPES::GROUP_ICON) + "' entry");
  }
  uint16_t new_id = static_cast<uint16_t>(icon.id());

  if (static_cast<int32_t>(icon.id()) < 0) {
    new_id = it_icon->childs().size() + 1;
  }

  // Add to the GROUP
  ResourceData* icon_group_node = dynamic_cast<ResourceData*>(&((*it_grp_icon).childs()[0].childs()[0]));
  std::vector<uint8_t> icon_group_content = icon_group_node->content();

  pe_resource_icon_dir* group_icon_header = reinterpret_cast<pe_resource_icon_dir*>(icon_group_content.data());

  pe_resource_icon_group new_icon_header;

  new_icon_header.width       = icon.width();
  new_icon_header.height      = icon.height();
  new_icon_header.color_count = icon.color_count();
  new_icon_header.reserved    = icon.reserved();
  new_icon_header.planes      = icon.planes();
  new_icon_header.bit_count   = icon.bit_count();
  new_icon_header.size        = icon.size();
  new_icon_header.ID          = new_id;

  icon_group_content.insert(
      std::begin(icon_group_content) +
      sizeof(pe_resource_icon_dir) +
      group_icon_header->count * sizeof(pe_resource_icon_group),
      reinterpret_cast<uint8_t*>(&new_icon_header),
      reinterpret_cast<uint8_t*>(&new_icon_header) + sizeof(pe_resource_icon_group));

  group_icon_header->count++;

  icon_group_node->content(icon_group_content);

  // Add to the ICON list
  ResourceDirectory new_icon_dir_node;
  new_icon_dir_node.id(new_id);

  ResourceData new_icon_data_node{icon.pixels(), 0};
  new_icon_data_node.id(icon.sublang() << 10 | icon.lang());
  new_icon_dir_node.add_child(new_icon_data_node);

  it_icon->add_child(new_icon_dir_node);
  it_icon->sort_by_id();
}


void ResourcesManager::change_icon(const ResourceIcon& original, const ResourceIcon& newone) {
  it_childs nodes = this->resources_->childs();
  auto&& it_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::ICON;
      });


  auto&& it_grp_icon = std::find_if(
      std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return node.id() == RESOURCE_TYPES::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    throw not_found(std::string("Missing '") + to_string(RESOURCE_TYPES::ICON) + "' entry");
  }


  // 1. Update group in which the icon is registred
  // ----------------------------------------------
  pe_resource_icon_group* group = nullptr;
  for (ResourceNode& grp_icon_lvl2 : it_grp_icon->childs()) {
    for (ResourceNode& grp_icon_lvl3 : grp_icon_lvl2.childs()) {
      ResourceData* icon_group_node = dynamic_cast<ResourceData*>(&grp_icon_lvl3);

      std::vector<uint8_t> icon_group_content = icon_group_node->content();

      pe_resource_icon_dir* group_icon_header = reinterpret_cast<pe_resource_icon_dir*>(icon_group_content.data());
      for (size_t i = 0; i < group_icon_header->count; ++i) {
        pe_resource_icon_group* icon_header = reinterpret_cast<pe_resource_icon_group*>(
            icon_group_content.data() +
            sizeof(pe_resource_icon_dir) +
            i * sizeof(pe_resource_icon_group));

        if (icon_header->ID == original.id()) {
          VLOG(VDEBUG) << "Group found: " << std::dec << i << "-nth";
          group = icon_header;
          icon_header->width       = newone.width();
          icon_header->height      = newone.height();
          icon_header->color_count = newone.color_count();
          icon_header->reserved    = newone.reserved();
          icon_header->planes      = newone.planes();
          icon_header->bit_count   = newone.bit_count();
          icon_header->size        = newone.size();
          icon_header->ID          = newone.id();
        }
      }

      if (group == nullptr) {
        throw not_found("Unable to find the group associated with the original icon");
      }
      icon_group_node->content(icon_group_content);
    }
  }

  // 2. Update icons
  // ---------------
  it_icon->delete_child(original.id());
  ResourceDirectory new_icon_dir_node;
  new_icon_dir_node.id(newone.id());

  ResourceData new_icon_data_node{newone.pixels(), 0};
  new_icon_data_node.id(newone.sublang() << 10 | newone.lang());
  new_icon_dir_node.add_child(new_icon_data_node);

  it_icon->add_child(new_icon_dir_node);
  it_icon->sort_by_id();
}

// Dialogs
// See:
// * https://msdn.microsoft.com/en-us/library/ms645398.aspx
// * https://msdn.microsoft.com/en-us/library/ms645389.aspx
// * https://blogs.msdn.microsoft.com/oldnewthing/20110330-00/?p=11093
// TODO:
// * Menu as ordinal
// * Windows class as ordinal
// * Extra count
// ====================================================================
std::vector<ResourceDialog> ResourcesManager::dialogs(void) const {
  if (not this->has_dialogs()) {
    throw not_found("No dialogs found!");
  }
  std::vector<ResourceDialog> dialogs;
  const ResourceDirectory* dialog_dir = dynamic_cast<const ResourceDirectory*>(&this->get_node_type(RESOURCE_TYPES::DIALOG));

  it_const_childs nodes = dialog_dir->childs();
  for (size_t i = 0; i < nodes.size(); ++i) {

    const ResourceDirectory* dialog = dynamic_cast<const ResourceDirectory*>(&nodes[i]);
    it_const_childs langs = dialog->childs();

    for (size_t j = 0; j < langs.size(); ++j) {
      const ResourceData* data_node = dynamic_cast<const ResourceData*>(&langs[j]);
      const std::vector<uint8_t>& content = data_node->content();
      VectorStream stream{content};


      if (content.size() < std::min(sizeof(pe_dialog_template_ext), sizeof(pe_dialog_template))) {
        throw corrupted("Dialog is corrupted!");
      }

      if (content[2] == 0xFF and content[3] == 0xFF) {

        if (content.size() < sizeof(pe_dialog_template_ext)) {
          throw corrupted("Dialog is corrupted!");
        }

        const pe_dialog_template_ext* header = reinterpret_cast<const pe_dialog_template_ext*>(stream.read(0, sizeof(pe_dialog_template_ext)));

        ResourceDialog new_dialog{header};

        size_t offset = sizeof(pe_dialog_template_ext);

        // Menu
        // ====
        const uint16_t menu_hint = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
        offset += sizeof(uint16_t);
        switch(menu_hint) {
          case 0x0000:
            {
              VLOG(VDEBUG) << "Dialog has not menu";
              break;
            }

          case 0xFFFF:
            {
              const uint16_t menu_ordinal = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
              offset += sizeof(uint16_t);
              VLOG(VDEBUG) << "Menu uses ordinal number " << std::dec << menu_ordinal;
              break;
            }

          default:
            {
              VLOG(VDEBUG) << "Menu uses unicode string";
              std::u16string menu_name = {reinterpret_cast<const char16_t*>(content.data() + offset)};
              offset += (menu_name.size() + 1)* sizeof(char16_t);
            }
        }

        // Window Class
        // ============
        const uint16_t window_class_hint = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
        offset += sizeof(uint16_t);
        switch(window_class_hint) {
          case 0x0000:
            {
              VLOG(VDEBUG) << "Windows class uses predefined dialog box";
              break;
            }

          case 0xFFFF:
            {
              const uint16_t windows_class_ordinal = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
              VLOG(VDEBUG) << "Windows class uses ordinal number " << std::dec <<  windows_class_ordinal;
              offset += sizeof(uint16_t);
              break;
            }

          default:
            {

              VLOG(VDEBUG) << "Windows class uses unicode string";
              std::u16string window_class_name = {reinterpret_cast<const char16_t*>(content.data() + offset)};
              offset += (window_class_name.size() + 1) * sizeof(char16_t);
            }
        }

        // Title
        // =====
        VLOG(VDEBUG) << "Title offset: " << std::hex << offset;
        new_dialog.title_ = std::u16string{reinterpret_cast<const char16_t*>(content.data() + offset)};
        offset += sizeof(uint16_t) * (new_dialog.title().size() + 1);

        // 2nd part
        // ========
        const std::set<DIALOG_BOX_STYLES>& dialogbox_styles = new_dialog.dialogbox_style_list();
        if (dialogbox_styles.count(DIALOG_BOX_STYLES::DS_SHELLFONT) > 0 or dialogbox_styles.count(DIALOG_BOX_STYLES::DS_SETFONT) > 0) {
          const uint16_t point_size = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
          offset += sizeof(uint16_t);
          new_dialog.point_size_ = point_size;

          const uint16_t weight = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
          offset += sizeof(uint16_t);
          new_dialog.weight_ = weight;

          const uint8_t is_italic = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
          offset += sizeof(uint8_t);
          new_dialog.italic_ = static_cast<bool>(is_italic);

          const uint8_t charset = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
          offset += sizeof(uint8_t);
          new_dialog.charset_ = static_cast<bool>(charset);

          new_dialog.typeface_ = std::u16string{reinterpret_cast<const char16_t*>(content.data() + offset)};
          offset += (new_dialog.typeface().size() + 1) * sizeof(char16_t);
        }

        VLOG(VDEBUG) << "Offset to the items: 0x" << std::hex << offset;
        VLOG(VDEBUG) << std::endl << std::endl << "####### Items #######" << std::endl;

        // Items
        // =====
        for (size_t i = 0; i < header->nbof_items; ++i) {
          offset = align(offset, sizeof(uint32_t));
          VLOG(VDEBUG) << "item[" << std::dec << i << "] offset: 0x" << std::hex << offset;
          ResourceDialogItem dialog_item;

          if (new_dialog.is_extended()) {
            const pe_dialog_item_template_ext* item_header = reinterpret_cast<const pe_dialog_item_template_ext*>(stream.read(offset, sizeof(pe_dialog_item_template_ext)));
            offset += sizeof(pe_dialog_item_template_ext);
            dialog_item = {item_header};
            VLOG(VDEBUG) << "Item ID: " << std::dec << item_header->id;
          } else {
            const pe_dialog_item_template* item_header = reinterpret_cast<const pe_dialog_item_template*>(stream.read(offset, sizeof(pe_dialog_item_template)));
            offset += sizeof(pe_dialog_item_template);
            new_dialog.items_.emplace_back(item_header);
            continue;
          }

          // window class
          // ------------
          offset = align(offset, sizeof(uint32_t));
          const uint16_t window_class_hint = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
          offset += sizeof(uint16_t);
          if (window_class_hint == 0xFFFF) {
            const uint16_t windows_class_ordinal = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
            VLOG(VDEBUG) << "Windows class uses ordinal number " << std::dec <<  windows_class_ordinal;
            offset += sizeof(uint16_t);
          } else {
            VLOG(VDEBUG) << "Windows class uses unicode string";
            std::u16string window_class_name = {reinterpret_cast<const char16_t*>(stream.read(offset, sizeof(uint16_t)))};
            offset += (window_class_name.size() + 1) * sizeof(char16_t);
          }

          // Title
          // -----
          offset = align(offset, sizeof(uint32_t));
          const uint16_t title_hint = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));

          if (title_hint == 0xFFFF) {
            offset += sizeof(uint16_t);
            const uint16_t title_ordinal = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
            VLOG(VDEBUG) << "Title uses ordinal number " << std::dec <<  title_ordinal;
            offset += sizeof(uint16_t);
          } else {
            std::u16string title_name = {reinterpret_cast<const char16_t*>(content.data() + offset)};
            offset += (title_name.size() + 1) * sizeof(char16_t);
            VLOG(VDEBUG) << "Title uses unicode string: \"" << u16tou8(title_name) << "\"";
            dialog_item.title_ = std::u16string{title_name};
          }

          // Extra count
          // -----------
          const uint16_t extra_count = *reinterpret_cast<const uint16_t*>(stream.read(offset, sizeof(uint16_t)));
          offset += sizeof(uint16_t);
          VLOG(VDEBUG) << "Extra count: " << std::hex << extra_count << std::endl;
          dialog_item.extra_count_ = extra_count;
          offset += extra_count * sizeof(uint8_t);
          new_dialog.items_.push_back(std::move(dialog_item));
        }

        dialogs.push_back(std::move(new_dialog));
      }
    }
  }
  return dialogs;
}


bool ResourcesManager::has_dialogs(void) const {
  return this->has_type(RESOURCE_TYPES::DIALOG);
}

// Prints
// ======

std::string ResourcesManager::print(uint32_t depth) const {
  std::ostringstream oss;
  oss << rang::control::forceColor;
  uint32_t current_depth = 0;
  this->print_tree(*this->resources_, oss, current_depth, depth);
  return oss.str();
}

void ResourcesManager::print_tree(
    const ResourceNode& node,
    std::ostringstream& output,
    uint32_t current_depth,
    uint32_t max_depth) const {

  if (max_depth < current_depth) {
    return;
  }

  for (const ResourceNode& child_node : node.childs()) {
    output << std::string(2 * (current_depth + 1), ' ');
    output << "[";
    if (child_node.is_directory()) {
      output << rang::fg::cyan;
      output << "Directory";
    } else {
      output << rang::fg::yellow;
      output << "Data";
    }

    output << rang::style::reset;
    output << "] ";

    if (child_node.has_name()) {

      output << rang::bg::blue;
      output << u16tou8(child_node.name());
      output << rang::style::reset;
    } else {
      output << "ID: " << std::setw(2) << std::setfill('0') << std::dec << child_node.id();
      if (current_depth == 0) {
        output << " - " << to_string(static_cast<RESOURCE_TYPES>(child_node.id()));
      }

      if (current_depth == 2) {
        RESOURCE_SUBLANGS sub_lang = static_cast<RESOURCE_SUBLANGS>(child_node.id() >> 10);
        RESOURCE_LANGS lang        = static_cast<RESOURCE_LANGS>(child_node.id() & 0x3ff);
        output << " - " << to_string(lang) << "/" << to_string(sub_lang);
      }
      output << std::setfill(' ');
    }
    output << std::endl;
    print_tree(child_node, output, current_depth + 1, max_depth);
  }

}

void ResourcesManager::accept(Visitor& visitor) const {
  if (this->has_manifest()) {
    visitor.visit(this->manifest());
  }

  if (this->has_version()) {
    visitor(this->version());
  }

  if (this->has_icons()) {
    for (const ResourceIcon& icon : this->icons()) {
      visitor(icon);
    }
  }

  if (this->has_dialogs()) {
    for (const ResourceDialog& dialog : this->dialogs()) {
      visitor(dialog);
    }
  }

}

bool ResourcesManager::operator==(const ResourcesManager& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourcesManager::operator!=(const ResourcesManager& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourcesManager& rsrc) {
  os << rsrc.print(3);
  os << std::endl;

  std::set<RESOURCE_TYPES> types = rsrc.get_types_available();
  std::set<RESOURCE_LANGS> langs = rsrc.get_langs_available();
  std::set<RESOURCE_SUBLANGS> sublangs = rsrc.get_sublangs_available();

  if (types.size() > 0) {
    std::string types_str = std::accumulate(
        std::begin(types),
        std::end(types), std::string{},
        [] (std::string a, RESOURCE_TYPES t) {
         return a.empty() ? to_string(t) : a + " - " + to_string(t);
        });
    os << "Types: " << types_str << std::endl << std::endl;
  }


  if (langs.size() > 0) {
    std::string langs_str = std::accumulate(
        std::begin(langs),
        std::end(langs), std::string{},
        [] (std::string a, RESOURCE_LANGS l) {
         return a.empty() ? to_string(l) : a + " - " + to_string(l);
        });
    os << "Langs: " << langs_str << std::endl << std::endl;
  }


  if (sublangs.size() > 0) {
    std::string sublangs_str = std::accumulate(
        std::begin(sublangs),
        std::end(sublangs), std::string{},
        [] (std::string a, RESOURCE_SUBLANGS sl) {
         return a.empty() ? to_string(sl) : a + " - " + to_string(sl);
        });
    os << "Sub-langs: " << sublangs_str << std::endl << std::endl;
  }


  if (rsrc.has_manifest()) {
    os << "Manifest" << std::endl;
    os << "========" << std::endl << std::endl;
    os << rsrc.manifest();
    os << std::endl << std::endl;
  }


  if (rsrc.has_version()) {
    os << "Version" << std::endl;
    os << "=======" << std::endl << std::endl;
    try {
      os << rsrc.version();
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
    os << std::endl;
  }

  if (rsrc.has_icons()) {
    try {
      const std::vector<ResourceIcon>& icons = rsrc.icons();
      for (size_t i = 0; i < icons.size(); ++i) {
        os << "Icon #" << std::dec << i << " : " << std::endl;
        os << icons[i] << std::endl;
      }
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }


  if (rsrc.has_dialogs()) {
    try {
      const std::vector<ResourceDialog>& dialogs = rsrc.dialogs();
      for (size_t i = 0; i < dialogs.size(); ++i) {
        os << "Dialog #" << std::dec << i << " : " << std::endl;
        os << dialogs[i] << std::endl;
      }
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }


  return os;
}

} // namespace PE
} // namespace LIEF
