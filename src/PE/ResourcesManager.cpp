/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#include <utility>

#include "logging.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/PE/hash.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include "LIEF/PE/resources/LangCodeItem.hpp"
#include "LIEF/PE/resources/ResourceStringTable.hpp"
#include "LIEF/PE/resources/ResourceAccelerator.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"
#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"
#include "PE/Structures.hpp"
#include "PE/ResourcesParser.hpp"

namespace LIEF {
namespace PE {


ResourcesManager::ResourcesManager(ResourcesManager&&) = default;
ResourcesManager& ResourcesManager::operator=(ResourcesManager&&) = default;

ResourcesManager::ResourcesManager(const ResourcesManager&) = default;
ResourcesManager& ResourcesManager::operator=(const ResourcesManager&) = default;
ResourcesManager::~ResourcesManager() = default;

ResourcesManager::ResourcesManager(ResourceNode& rsrc) :
  resources_{&rsrc}
{}

RESOURCE_LANGS ResourcesManager::lang_from_id(size_t id) {
  return static_cast<RESOURCE_LANGS>(id & 0x3ff);
}

RESOURCE_SUBLANGS ResourcesManager::sublang_from_id(size_t id) {
  const size_t index = id >> 10;
  const RESOURCE_LANGS lang = ResourcesManager::lang_from_id(id);
  return ResourcesManager::sub_lang(lang, index);
}

RESOURCE_SUBLANGS ResourcesManager::sub_lang(RESOURCE_LANGS lang, size_t index) {
  // From https://docs.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings
  static const std::map<std::pair<RESOURCE_LANGS, size_t>, RESOURCE_SUBLANGS> sublangs_map = {

    { {RESOURCE_LANGS::LANG_ARABIC, 0x5}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_ALGERIA },
    { {RESOURCE_LANGS::LANG_ARABIC, 0xF}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_BAHRAIN },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x3}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_EGYPT },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x2}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_IRAQ },
    { {RESOURCE_LANGS::LANG_ARABIC, 0xB}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_JORDAN },
    { {RESOURCE_LANGS::LANG_ARABIC, 0xD}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_KUWAIT },
    { {RESOURCE_LANGS::LANG_ARABIC, 0xC}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_LEBANON },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x4}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_LIBYA },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x6}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_MOROCCO },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x8}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_OMAN },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x10}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_QATAR },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x01}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_SAUDI_ARABIA },
    { {RESOURCE_LANGS::LANG_ARABIC, 0xA}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_SYRIA },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x7}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_TUNISIA },
    { {RESOURCE_LANGS::LANG_ARABIC, 0xE}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_UAE },
    { {RESOURCE_LANGS::LANG_ARABIC, 0x9}, RESOURCE_SUBLANGS::SUBLANG_ARABIC_YEMEN },

    { {RESOURCE_LANGS::LANG_AZERI, 2}, RESOURCE_SUBLANGS::SUBLANG_AZERI_CYRILLIC },
    { {RESOURCE_LANGS::LANG_AZERI, 1}, RESOURCE_SUBLANGS::SUBLANG_AZERI_LATIN },

    { {RESOURCE_LANGS::LANG_BANGLA, 2}, RESOURCE_SUBLANGS::SUBLANG_BANGLA_BANGLADESH },
    { {RESOURCE_LANGS::LANG_BANGLA, 1}, RESOURCE_SUBLANGS::SUBLANG_BANGLA_INDIA },

    { {RESOURCE_LANGS::LANG_BOSNIAN, 8}, RESOURCE_SUBLANGS::SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC },
    { {RESOURCE_LANGS::LANG_BOSNIAN, 5}, RESOURCE_SUBLANGS::SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN },

    { {RESOURCE_LANGS::LANG_CHINESE, 3}, RESOURCE_SUBLANGS::SUBLANG_CHINESE_HONGKONG },
    { {RESOURCE_LANGS::LANG_CHINESE, 5}, RESOURCE_SUBLANGS::SUBLANG_CHINESE_MACAU },
    { {RESOURCE_LANGS::LANG_CHINESE, 4}, RESOURCE_SUBLANGS::SUBLANG_CHINESE_SINGAPORE },
    { {RESOURCE_LANGS::LANG_CHINESE, 2}, RESOURCE_SUBLANGS::SUBLANG_CHINESE_SIMPLIFIED },

    { {RESOURCE_LANGS::LANG_CROATIAN, 4}, RESOURCE_SUBLANGS::SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN },
    { {RESOURCE_LANGS::LANG_CROATIAN, 1}, RESOURCE_SUBLANGS::SUBLANG_CROATIAN_CROATIA },

    { {RESOURCE_LANGS::LANG_DUTCH, 2}, RESOURCE_SUBLANGS::SUBLANG_DUTCH_BELGIAN },
    { {RESOURCE_LANGS::LANG_DUTCH, 2}, RESOURCE_SUBLANGS::SUBLANG_DUTCH },

    { {RESOURCE_LANGS::LANG_ENGLISH, 0x3}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_AUS },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0xA}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_BELIZE },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x4}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_CAN },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x9}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_CARIBBEAN },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x10}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_IRELAND },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x6}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_JAMAICA },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x8}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_MALAYSIA },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x11}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_NZ },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x5}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_PHILIPPINES },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x12}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_SINGAPORE },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x7}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_SOUTH_AFRICA },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0xB}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_TRINIDAD },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x2}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_UK },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0x1}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_US },
    { {RESOURCE_LANGS::LANG_ENGLISH, 0xC}, RESOURCE_SUBLANGS::SUBLANG_ENGLISH_ZIMBABWE },

    { {RESOURCE_LANGS::LANG_FRENCH, 1}, RESOURCE_SUBLANGS::SUBLANG_FRENCH },
    { {RESOURCE_LANGS::LANG_FRENCH, 2}, RESOURCE_SUBLANGS::SUBLANG_FRENCH_BELGIAN },
    { {RESOURCE_LANGS::LANG_FRENCH, 3}, RESOURCE_SUBLANGS::SUBLANG_FRENCH_CANADIAN },
    { {RESOURCE_LANGS::LANG_FRENCH, 5}, RESOURCE_SUBLANGS::SUBLANG_FRENCH_LUXEMBOURG },
    { {RESOURCE_LANGS::LANG_FRENCH, 6}, RESOURCE_SUBLANGS::SUBLANG_FRENCH_MONACO },
    { {RESOURCE_LANGS::LANG_FRENCH, 4}, RESOURCE_SUBLANGS::SUBLANG_FRENCH_SWISS },

    { {RESOURCE_LANGS::LANG_GERMAN, 1}, RESOURCE_SUBLANGS::SUBLANG_GERMAN },
    { {RESOURCE_LANGS::LANG_GERMAN, 3}, RESOURCE_SUBLANGS::SUBLANG_GERMAN_AUSTRIAN },
    { {RESOURCE_LANGS::LANG_GERMAN, 5}, RESOURCE_SUBLANGS::SUBLANG_GERMAN_LIECHTENSTEIN },
    { {RESOURCE_LANGS::LANG_GERMAN, 4}, RESOURCE_SUBLANGS::SUBLANG_GERMAN_LUXEMBOURG },
    { {RESOURCE_LANGS::LANG_GERMAN, 2}, RESOURCE_SUBLANGS::SUBLANG_GERMAN_SWISS },

    { {RESOURCE_LANGS::LANG_INUKTITUT, 1}, RESOURCE_SUBLANGS::SUBLANG_INUKTITUT_CANADA },
    { {RESOURCE_LANGS::LANG_INUKTITUT, 2}, RESOURCE_SUBLANGS::SUBLANG_INUKTITUT_CANADA_LATIN },

    { {RESOURCE_LANGS::LANG_IRISH, 2}, RESOURCE_SUBLANGS::SUBLANG_IRISH_IRELAND },

    { {RESOURCE_LANGS::LANG_ITALIAN, 1}, RESOURCE_SUBLANGS::SUBLANG_ITALIAN },
    { {RESOURCE_LANGS::LANG_ITALIAN, 2}, RESOURCE_SUBLANGS::SUBLANG_ITALIAN_SWISS },

    { {RESOURCE_LANGS::LANG_LOWER_SORBIAN, 2}, RESOURCE_SUBLANGS::SUBLANG_LOWER_SORBIAN_GERMANY },

    { {RESOURCE_LANGS::LANG_MALAY, 2}, RESOURCE_SUBLANGS::SUBLANG_MALAY_BRUNEI_DARUSSALAM },
    { {RESOURCE_LANGS::LANG_MALAY, 1}, RESOURCE_SUBLANGS::SUBLANG_MALAY_MALAYSIA },

    { {RESOURCE_LANGS::LANG_MONGOLIAN, 2}, RESOURCE_SUBLANGS::SUBLANG_MONGOLIAN_PRC },
    { {RESOURCE_LANGS::LANG_MONGOLIAN, 1}, RESOURCE_SUBLANGS::SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA },

    { {RESOURCE_LANGS::LANG_NEPALI, 2}, RESOURCE_SUBLANGS::SUBLANG_NEPALI_INDIA },
    { {RESOURCE_LANGS::LANG_NEPALI, 1}, RESOURCE_SUBLANGS::SUBLANG_NEPALI_NEPAL },

    { {RESOURCE_LANGS::LANG_NORWEGIAN, 1}, RESOURCE_SUBLANGS::SUBLANG_NORWEGIAN_BOKMAL },
    { {RESOURCE_LANGS::LANG_NORWEGIAN, 2}, RESOURCE_SUBLANGS::SUBLANG_NORWEGIAN_NYNORSK },

    { {RESOURCE_LANGS::LANG_PORTUGUESE, 2}, RESOURCE_SUBLANGS::SUBLANG_PORTUGUESE },
    { {RESOURCE_LANGS::LANG_PORTUGUESE, 1}, RESOURCE_SUBLANGS::SUBLANG_PORTUGUESE_BRAZILIAN },

    { {RESOURCE_LANGS::LANG_PULAR, 2}, RESOURCE_SUBLANGS::SUBLANG_PULAR_SENEGAL },

    { {RESOURCE_LANGS::LANG_PUNJABI, 1}, RESOURCE_SUBLANGS::SUBLANG_PUNJABI_INDIA },
    { {RESOURCE_LANGS::LANG_PUNJABI, 2}, RESOURCE_SUBLANGS::SUBLANG_PUNJABI_PAKISTAN },

    { {RESOURCE_LANGS::LANG_QUECHUA, 1}, RESOURCE_SUBLANGS::SUBLANG_QUECHUA_BOLIVIA },
    { {RESOURCE_LANGS::LANG_QUECHUA, 2}, RESOURCE_SUBLANGS::SUBLANG_QUECHUA_ECUADOR },
    { {RESOURCE_LANGS::LANG_QUECHUA, 3}, RESOURCE_SUBLANGS::SUBLANG_QUECHUA_PERU },

    { {RESOURCE_LANGS::LANG_SAMI, 9}, RESOURCE_SUBLANGS::SUBLANG_SAMI_INARI_FINLAND },
    { {RESOURCE_LANGS::LANG_SAMI, 4}, RESOURCE_SUBLANGS::SUBLANG_SAMI_LULE_NORWAY },
    { {RESOURCE_LANGS::LANG_SAMI, 5}, RESOURCE_SUBLANGS::SUBLANG_SAMI_LULE_SWEDEN },
    { {RESOURCE_LANGS::LANG_SAMI, 3}, RESOURCE_SUBLANGS::SUBLANG_SAMI_NORTHERN_FINLAND },
    { {RESOURCE_LANGS::LANG_SAMI, 2}, RESOURCE_SUBLANGS::SUBLANG_SAMI_NORTHERN_SWEDEN },
    { {RESOURCE_LANGS::LANG_SAMI, 8}, RESOURCE_SUBLANGS::SUBLANG_SAMI_SKOLT_FINLAND },
    { {RESOURCE_LANGS::LANG_SAMI, 6}, RESOURCE_SUBLANGS::SUBLANG_SAMI_SOUTHERN_NORWAY },
    { {RESOURCE_LANGS::LANG_SAMI, 7}, RESOURCE_SUBLANGS::SUBLANG_SAMI_SOUTHERN_SWEDEN },
    { {RESOURCE_LANGS::LANG_SAMI, 1}, RESOURCE_SUBLANGS::SUBLANG_SAMI_NORTHERN_NORWAY },

    { {RESOURCE_LANGS::LANG_SERBIAN, 7}, RESOURCE_SUBLANGS::SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC },
    { {RESOURCE_LANGS::LANG_SERBIAN, 6}, RESOURCE_SUBLANGS::SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN },
    { {RESOURCE_LANGS::LANG_SERBIAN, 1}, RESOURCE_SUBLANGS::SUBLANG_SERBIAN_CROATIA },
    { {RESOURCE_LANGS::LANG_SERBIAN, 3}, RESOURCE_SUBLANGS::SUBLANG_SERBIAN_CYRILLIC },
    { {RESOURCE_LANGS::LANG_SERBIAN, 2}, RESOURCE_SUBLANGS::SUBLANG_SERBIAN_LATIN },

    { {RESOURCE_LANGS::LANG_TSWANA, 2}, RESOURCE_SUBLANGS::SUBLANG_TSWANA_BOTSWANA },
    { {RESOURCE_LANGS::LANG_TSWANA, 1}, RESOURCE_SUBLANGS::SUBLANG_TSWANA_SOUTH_AFRICA },

    { {RESOURCE_LANGS::LANG_SPANISH, 0xb}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_ARGENTINA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x10}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_BOLIVIA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0xd}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_CHILE },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x9}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_COLOMBIA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x5}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_COSTA_RICA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x7}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_DOMINICAN_REPUBLIC },
    { {RESOURCE_LANGS::LANG_SPANISH, 0xC}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_ECUADOR },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x11}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_EL_SALVADOR },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x4}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_GUATEMALA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x12}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_HONDURAS },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x2}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_MEXICAN },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x13}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_NICARAGUA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x6}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_PANAMA },
    { {RESOURCE_LANGS::LANG_SPANISH, 0xF}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_PARAGUAY },
    { {RESOURCE_LANGS::LANG_SPANISH, 0xA}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_PERU },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x14}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_PUERTO_RICO },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x3}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_MODERN },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x1}, RESOURCE_SUBLANGS::SUBLANG_SPANISH },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x15}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_US },
    { {RESOURCE_LANGS::LANG_SPANISH, 0xE}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_URUGUAY },
    { {RESOURCE_LANGS::LANG_SPANISH, 0x8}, RESOURCE_SUBLANGS::SUBLANG_SPANISH_VENEZUELA },

    { {RESOURCE_LANGS::LANG_SWEDISH, 2}, RESOURCE_SUBLANGS::SUBLANG_SWEDISH_FINLAND },
    { {RESOURCE_LANGS::LANG_SWEDISH, 1}, RESOURCE_SUBLANGS::SUBLANG_SWEDISH },

    { {RESOURCE_LANGS::LANG_TAMAZIGHT, 2}, RESOURCE_SUBLANGS::SUBLANG_TAMAZIGHT_ALGERIA_LATIN },

    { {RESOURCE_LANGS::LANG_TAMIL, 1}, RESOURCE_SUBLANGS::SUBLANG_TAMIL_INDIA },
    { {RESOURCE_LANGS::LANG_TAMIL, 2}, RESOURCE_SUBLANGS::SUBLANG_TAMIL_SRI_LANKA },

    { {RESOURCE_LANGS::LANG_TIGRINYA, 1}, RESOURCE_SUBLANGS::SUBLANG_TIGRINYA_ETHIOPIA },
    { {RESOURCE_LANGS::LANG_TIGRINYA, 2}, RESOURCE_SUBLANGS::SUBLANG_TIGRINYA_ERITREA },

    { {RESOURCE_LANGS::LANG_TIGRINYA, 1}, RESOURCE_SUBLANGS::SUBLANG_UIGHUR_PRC },
    { {RESOURCE_LANGS::LANG_TIGRINYA, 2}, RESOURCE_SUBLANGS::SUBLANG_UZBEK_CYRILLIC },

    { {RESOURCE_LANGS::LANG_VALENCIAN, 2}, RESOURCE_SUBLANGS::SUBLANG_VALENCIAN_VALENCIA },
  };

  const auto it = sublangs_map.find({lang, index});
  if (it == std::end(sublangs_map)) {
    return RESOURCE_SUBLANGS::SUBLANG_DEFAULT;
  }
  return it->second;
}


// Enhancemed API to explore resource tree
// =======================================

ResourceNode* ResourcesManager::get_node_type(RESOURCE_TYPES type) {
  return const_cast<ResourceNode*>(static_cast<const ResourcesManager*>(this)->get_node_type(type));
}

const ResourceNode* ResourcesManager::get_node_type(RESOURCE_TYPES type) const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_node = std::find_if(std::begin(nodes), std::end(nodes),
      [type] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == type;
      });

  if (it_node == std::end(nodes)) {
    return nullptr;
  }

  return &*it_node;
}

std::set<RESOURCE_TYPES> ResourcesManager::get_types_available() const {
  std::set<RESOURCE_TYPES> types;
  for (const ResourceNode& node : resources_->childs()) {
    const auto *const it = std::find_if(std::begin(resource_types_array), std::end(resource_types_array),
        [&node] (RESOURCE_TYPES t) {
          return t == static_cast<RESOURCE_TYPES>(node.id());
        });
    if (it != std::end(resource_types_array)) {
      types.insert(*it);
    }
  }
  return types;

}

std::set<RESOURCE_LANGS> ResourcesManager::get_langs_available() const {
  std::set<RESOURCE_LANGS> langs;
  for (const ResourceNode& node_lvl_1 : resources_->childs()) {
    for (const ResourceNode& node_lvl_2 : node_lvl_1.childs()) {
      for (const ResourceNode& node_lvl_3 : node_lvl_2.childs()) {

        auto lang = static_cast<RESOURCE_LANGS>(node_lvl_3.id() & 0x3ff);
        const auto *const it = std::find_if(std::begin(resource_langs_array), std::end(resource_langs_array),
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

std::set<RESOURCE_SUBLANGS> ResourcesManager::get_sublangs_available() const {
  std::set<RESOURCE_SUBLANGS> sublangs;
  for (const ResourceNode& node_lvl_1 : resources_->childs()) {
    for (const ResourceNode& node_lvl_2 : node_lvl_1.childs()) {
      for (const ResourceNode& node_lvl_3 : node_lvl_2.childs()) {
        RESOURCE_SUBLANGS sub_lang = ResourcesManager::sublang_from_id(node_lvl_3.id());
        sublangs.insert(sub_lang);
      }
    }
  }
  return sublangs;
}

bool ResourcesManager::has_type(RESOURCE_TYPES type) const {
  return get_node_type(type) != nullptr;
}


// Manifest
// ========

bool ResourcesManager::has_manifest() const {
  return get_node_type(RESOURCE_TYPES::MANIFEST) != nullptr;
}

std::string ResourcesManager::manifest() const {
  const ResourceNode* root_node = get_node_type(RESOURCE_TYPES::MANIFEST);
  if (root_node == nullptr) {
    LIEF_WARN("No manifest found in the resources");
    return "";
  }

  // First level of child nodes
  ResourceNode::it_const_childs childs_l1 = root_node->childs();
  if (childs_l1.empty()) {
    LIEF_ERR("Node {} empty", root_node->id());
    return "";
  }

  ResourceNode::it_childs childs_l2 = childs_l1[0].childs();
  if (childs_l2.empty()) {
    LIEF_ERR("Node {} empty", childs_l1->id());
    return "";
  }
  const ResourceNode& manifest_node = childs_l2[0];
  if (!manifest_node.is_data()) {
    LIEF_WARN("Expecting a Data Node");
    return "";
  }
  const auto& manifest_data = static_cast<const ResourceData&>(manifest_node);
  const std::vector<uint8_t>& content = manifest_data.content();
  return std::string{std::begin(content), std::end(content)};
}

void ResourcesManager::manifest(const std::string& manifest) {
  if (ResourceNode* manifest_node = get_node_type(RESOURCE_TYPES::MANIFEST)) {
    auto l1 = manifest_node->childs();
    if (l1.empty()) {
      LIEF_INFO("Can't update manifest: l1 empty");
      return;
    }
    auto l2 = l1[0].childs();
    if (l2.empty()) {
      LIEF_INFO("Can't update manifest: l2 empty");
      return;
    }
    ResourceNode& mnode = l2[0];
    if (!mnode.is_data()) {
      LIEF_INFO("Can't update manifest: l2 is not a data node");
      return;
    }
    auto& data = static_cast<ResourceData&>(mnode);
    data.content({std::begin(manifest), std::end(manifest)});
  }
  LIEF_INFO("No manifest. We can't create a new one");
  return;
}


// Resource Version
// ================
bool ResourcesManager::has_version() const {
  return get_node_type(RESOURCE_TYPES::VERSION) != nullptr;
}

result<ResourceVersion> ResourcesManager::version() const {
  const ResourceNode* root_node = get_node_type(RESOURCE_TYPES::VERSION);
  if (root_node == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  // First level of child nodes
  ResourceNode::it_const_childs childs_l1 = root_node->childs();
  if (childs_l1.empty()) {
    return make_error_code(lief_errors::corrupted);
  }

  ResourceNode::it_childs childs_l2 = childs_l1[0].childs();
  if (childs_l2.empty()) {
    return make_error_code(lief_errors::corrupted);
  }

  if (!childs_l2[0].is_data()) {
    return make_error_code(lief_errors::corrupted);
  }

  const auto& version_node = static_cast<const ResourceData&>(childs_l2[0]);
  const std::vector<uint8_t>& content = version_node.content();

  ResourceVersion version;
  if (auto stream = SpanStream::from_vector(content)) {
    if (auto version = ResourcesParser::parse_vs_versioninfo(*stream)) {
      return *version;
    }
  }
  return make_error_code(lief_errors::corrupted);
}

// Icons
// =====

bool ResourcesManager::has_icons() const {
  const ResourceNode* root_icon     = get_node_type(RESOURCE_TYPES::ICON);
  const ResourceNode* root_grp_icon = get_node_type(RESOURCE_TYPES::GROUP_ICON);
  return root_icon != nullptr && root_grp_icon != nullptr;
}

ResourcesManager::it_const_icons ResourcesManager::icons() const {
  std::vector<ResourceIcon> icons;
  const ResourceNode* root_icon     = get_node_type(RESOURCE_TYPES::ICON);
  const ResourceNode* root_grp_icon = get_node_type(RESOURCE_TYPES::GROUP_ICON);
  if (root_icon == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::ICON));
    return icons;
  }

  if (root_grp_icon == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::GROUP_ICON));
    return icons;
  }

  for (const ResourceNode& grp_icon_lvl2 : root_grp_icon->childs()) {
    for (const ResourceNode& grp_icon_lvl3 : grp_icon_lvl2.childs()) {
      if (!grp_icon_lvl3.is_data()) {
        LIEF_WARN("Expecting a data node for node id: {}", grp_icon_lvl3.id());
        continue;
      }
      const auto& icon_group_node = static_cast<const ResourceData&>(grp_icon_lvl3);
      const uint32_t id = icon_group_node.id();

      const std::vector<uint8_t>& icon_group_content = icon_group_node.content();
      if (icon_group_content.empty()) {
        LIEF_INFO("Group icon is empty");
        continue;
      }

      auto res_span = SpanStream::from_vector(icon_group_content);
      if (!res_span) {
        LIEF_WARN("Can't create a SpanStream from the content of the node id: {}", id);
        continue;
      }

      SpanStream stream = std::move(*res_span);
      details::pe_resource_icon_dir group_icon_header;
      if (auto res = stream.read<details::pe_resource_icon_dir>()) {
        group_icon_header = *res;
      } else {
        LIEF_WARN("Can't read GRPICONDIR for resource node id: {}", id);
        continue;
      }

      LIEF_DEBUG("GRPICONDIR.idType:  {}", group_icon_header.type);
      LIEF_DEBUG("GRPICONDIR.idCount: {}", group_icon_header.count);

      // Some checks
      if (group_icon_header.type != 1) {
        LIEF_ERR("Group icon type should be equal to 1 (vs {})", group_icon_header.type);
        return icons;
      }

      for (size_t i = 0; i < group_icon_header.count; ++i) {
        details::pe_resource_icon_group entry;
        if (auto res = stream.read<details::pe_resource_icon_group>()) {
          entry = *res;
        } else {
          LIEF_WARN("Can't read GRPICONDIR.idEntries[{}]", i);
          break;
        }

        ResourceIcon icon = entry;
        icon.lang_    = ResourcesManager::lang_from_id(grp_icon_lvl3.id());
        icon.sublang_ = ResourcesManager::sublang_from_id(grp_icon_lvl3.id());

        // Find the icon the RESOURCE_TYPES::ICON tree that matched entry.ID
        ResourceNode::it_const_childs sub_nodes_icons = root_icon->childs();
        const auto it = std::find_if(std::begin(sub_nodes_icons), std::end(sub_nodes_icons),
            [&entry] (const ResourceNode& node) {
              return node.id() == entry.ID;
            });
        if (it == std::end(sub_nodes_icons)) {
          LIEF_WARN("Unable to find the icon associated with id: {:d}", entry.ID);
          continue;
        }

        ResourceNode::it_childs icons_childs = it->childs();
        if (icons_childs.empty()) {
          LIEF_WARN("Resources nodes looks corrupted");
          continue;
        }
        const ResourceNode& icon_node = icons_childs[0];
        if (!icon_node.is_data()) {
          LIEF_WARN("Expecting a Data node for node id: {}", icon_node.id());
          continue;
        }
        const std::vector<uint8_t>& pixels = static_cast<const ResourceData&>(icon_node).content();
        icon.pixels_ = pixels;
        icons.push_back(std::move(icon));
      }
    }
  }

  return icons;
}


void ResourcesManager::add_icon(const ResourceIcon& icon) {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_icon = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::ICON;
      });


  const auto it_grp_icon = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::ICON));
    return;
  }

  if (it_grp_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::GROUP_ICON));
    return;
  }
  auto new_id = static_cast<uint16_t>(icon.id());

  if (static_cast<int32_t>(icon.id()) < 0) {
    new_id = it_icon->childs().size() + 1;
  }

  // Add to the GROUP

  // First level of child nodes
  ResourceNode::it_childs childs_l1 = it_icon->childs();
  if (childs_l1.size() < 1) {
    LIEF_ERR("Icon corrupted");
    return;
  }

  ResourceNode::it_childs childs_l2 = childs_l1[0].childs();

  if (childs_l2.size() < 1) {
    LIEF_ERR("Icon version corrupted");
    return;
  }

  if (!childs_l2[0].is_data()) {
    LIEF_ERR("Icon version corrupted");
    return;
  }
  auto& icon_group_node = reinterpret_cast<ResourceData&>(childs_l2[0]);
  std::vector<uint8_t> icon_group_content = icon_group_node.content();

  auto* group_icon_header = reinterpret_cast<details::pe_resource_icon_dir*>(icon_group_content.data());

  details::pe_resource_icon_group new_icon_header;

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
      sizeof(details::pe_resource_icon_dir) +
      group_icon_header->count * sizeof(details::pe_resource_icon_group),
      reinterpret_cast<uint8_t*>(&new_icon_header),
      reinterpret_cast<uint8_t*>(&new_icon_header) + sizeof(details::pe_resource_icon_group));

  group_icon_header->count++;

  icon_group_node.content(icon_group_content);

  // Add to the ICON list
  ResourceDirectory new_icon_dir_node;
  new_icon_dir_node.id(new_id);

  ResourceData new_icon_data_node{icon.pixels(), 0};
  new_icon_data_node.id(static_cast<int>(icon.sublang()) << 10 | static_cast<int>(icon.lang()));
  new_icon_dir_node.add_child(new_icon_data_node);

  it_icon->add_child(new_icon_dir_node);
}


void ResourcesManager::change_icon(const ResourceIcon& original, const ResourceIcon& newone) {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_icon = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::ICON;
      });


  const auto it_grp_icon = std::find_if(std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::ICON));
    return;
  }


  // 1. Update group in which the icon is registred
  // ----------------------------------------------
  details::pe_resource_icon_group* group = nullptr;
  for (ResourceNode& grp_icon_lvl2 : it_grp_icon->childs()) {
    for (ResourceNode& grp_icon_lvl3 : grp_icon_lvl2.childs()) {
      if (!grp_icon_lvl3.is_data()) {
        LIEF_WARN("Resource group icon corrupted");
        continue;
      }
      auto& icon_group_node = reinterpret_cast<ResourceData&>(grp_icon_lvl3);

      std::vector<uint8_t> icon_group_content = icon_group_node.content();

      auto* group_icon_header = reinterpret_cast<details::pe_resource_icon_dir*>(icon_group_content.data());
      for (size_t i = 0; i < group_icon_header->count; ++i) {
        auto* icon_header = reinterpret_cast<details::pe_resource_icon_group*>(
            icon_group_content.data() +
            sizeof(details::pe_resource_icon_dir) +
            i * sizeof(details::pe_resource_icon_group));

        if (icon_header->ID == original.id()) {
          LIEF_DEBUG("Group found: {:d}-nth", i);
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
        LIEF_ERR("Unable to find the group associated with the original icon");
        return;
      }
      icon_group_node.content(icon_group_content);
    }
  }

  // 2. Update icons
  // ---------------
  it_icon->delete_child(original.id());
  ResourceDirectory new_icon_dir_node;
  new_icon_dir_node.id(newone.id());

  ResourceData new_icon_data_node{newone.pixels(), 0};
  new_icon_data_node.id(static_cast<int>(newone.sublang()) << 10 | static_cast<int>(newone.lang()));
  new_icon_dir_node.add_child(new_icon_data_node);

  it_icon->add_child(new_icon_dir_node);
}

// Dialogs
// See:
// * https://docs.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
// * https://docs.microsoft.com/en-us/windows/win32/dlgbox/dlgitemtemplateex
// TODO:
// * Menu as ordinal
// * Windows class as ordinal
// * Extra count
// ====================================================================
ResourcesManager::it_const_dialogs ResourcesManager::dialogs() const {
  std::vector<ResourceDialog> dialogs;

  const ResourceNode* dialog_node = get_node_type(RESOURCE_TYPES::DIALOG);
  if (dialog_node == nullptr) {
    return dialogs;
  }

  if (!dialog_node->is_directory()) {
    LIEF_INFO("Expecting a Directory node for the Dialog Node");
    return dialogs;
  }
  const auto& dialog_dir = static_cast<const ResourceDirectory&>(*dialog_node);

  ResourceNode::it_const_childs nodes = dialog_dir.childs();
  for (size_t i = 0; i < nodes.size(); ++i) {
    if (!nodes[i].is_directory()) {
      LIEF_INFO("Expecting a Directory node for child #{}", i);
      continue;
    }

    const auto& dialog = static_cast<const ResourceDirectory&>(nodes[i]);
    ResourceNode::it_const_childs langs = dialog.childs();

    for (size_t j = 0; j < langs.size(); ++j) {
      if (!langs[j].is_data()) {
        LIEF_INFO("Expecting a Data node for child #{}->{}", i, j);
        continue;
      }

      const auto& data_node = static_cast<const ResourceData&>(langs[j]);
      const std::vector<uint8_t>& content = data_node.content();
      if (auto stream = SpanStream::from_vector(content)) {
        if (!ResourcesParser::parse_dialogs(dialogs, data_node, *stream)) {
          LIEF_INFO("Parsing resources dialogs #{}->{} finished with errors", i, j);
        }
      }
    }
  }
  return dialogs;
}


bool ResourcesManager::has_dialogs() const {
  return get_node_type(RESOURCE_TYPES::DIALOG) != nullptr;
}

// String table entry
ResourcesManager::it_const_strings_table ResourcesManager::string_table() const {
  std::vector<ResourceStringTable> string_table;
  const ResourceNode* root_node = get_node_type(RESOURCE_TYPES::STRING);
  if (root_node == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::STRING));
    return string_table;
  }

  for (const ResourceNode& child_l1 : root_node->childs()) {

    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_WARN("Expecting a data not for the string node id {}", child_l2.id());
        continue;
      }
      const auto& string_table_node = static_cast<const ResourceData&>(child_l2);
      const std::vector<uint8_t>& content = string_table_node.content();
      if (content.empty()) {
        LIEF_ERR("String table content is empty");
        continue;
      }

      auto stream_res = SpanStream::from_vector(content);
      if (!stream_res) {
        LIEF_INFO("Can't create a SpanStream for the string resource node");
        continue;
      }
      SpanStream stream = std::move(*stream_res);

      stream.setpos(0);
      LIEF_DEBUG("Will parse content with the size {}", stream.size());
      while (stream) {
        uint16_t len = 0;
        if (auto res = stream.read<uint16_t>()) {
          len = *res;
        } else {
          LIEF_INFO("Can't read the string len");
          break;
        }
        if (len == 0) {
          continue;
        }
        if (auto str = stream.read_u16string(len)) {
          string_table.emplace_back(ResourceStringTable(len, std::move(*str)));
        } else {
          LIEF_INFO("Error while trying to read the string");
          break;
        }
      }
    }
  }
  return string_table;
}

bool ResourcesManager::has_string_table() const {
  return get_node_type(RESOURCE_TYPES::STRING) != nullptr;
}

std::vector<std::string> ResourcesManager::html() const {
  const ResourceNode* root_node = get_node_type(RESOURCE_TYPES::HTML);
  if (root_node == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::HTML));
    return {};
  }
  std::vector<std::string> html;
  for (const ResourceNode& child_l1 : root_node->childs()) {
    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_ERR("html node corrupted");
        continue;
      }
      const auto& html_node = static_cast<const ResourceData&>(child_l2);

      const std::vector<uint8_t>& content = html_node.content();
      if (content.empty()) {
        LIEF_ERR("html content is empty");
        continue;
      }
      html.push_back(std::string{std::begin(content), std::end(content)});
    }
  }

  return html;
}

bool ResourcesManager::has_html() const {
  return get_node_type(RESOURCE_TYPES::HTML) != nullptr;
}

bool ResourcesManager::has_accelerator() const {
  return get_node_type(RESOURCE_TYPES::ACCELERATOR) != nullptr;
}

ResourcesManager::it_const_accelerators ResourcesManager::accelerator() const {
  std::vector<ResourceAccelerator> accelerator;
  const ResourceNode* root_node = get_node_type(RESOURCE_TYPES::ACCELERATOR);
  if (root_node == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::ACCELERATOR));
    return accelerator;
  }

  for (const ResourceNode& child_l1 : root_node->childs()) {
    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_ERR("Expecting a Data node for node id:: {}", child_l2.id());
        continue;
      }
      const auto& accelerator_node = static_cast<const ResourceData&>(child_l2);

      const std::vector<uint8_t>& content = accelerator_node.content();
      if (content.empty()) {
        LIEF_INFO("Accelerator content is empty");
        continue;
      }
      auto res_span = SpanStream::from_vector(content);
      if (!res_span) {
        LIEF_ERR("Can't create a span stream for node id: {}", accelerator_node.id());
        return accelerator;
      }
      SpanStream stream = std::move(*res_span);
      while (stream) {
        auto res_entry = stream.read<details::pe_resource_acceltableentry>();
        if (!res_entry) {
          LIEF_ERR("Can't read pe_resource_acceltableentry");
          break;
        }
        accelerator.emplace_back(ResourceAccelerator(std::move(*res_entry)));
      }
      if (!accelerator.empty()) {
        ResourceAccelerator& acc = accelerator.back();
        if ((acc.flags() & int16_t(ACCELERATOR_FLAGS::END)) != int16_t(ACCELERATOR_FLAGS::END)) {
          LIEF_ERR("Accelerator resources might be corrupted");
        }
      }
    }
  }

  return accelerator;
}

// Prints
// ======

std::string ResourcesManager::print(uint32_t depth) const {
  std::ostringstream oss;
  uint32_t current_depth = 0;
  print_tree(*resources_, oss, current_depth, depth);
  return oss.str();
}

void ResourcesManager::print_tree(const ResourceNode& node, std::ostringstream& output,
                                  uint32_t current_depth, uint32_t max_depth) const
{

  if (max_depth < current_depth) {
    return;
  }

  for (const ResourceNode& child_node : node.childs()) {
    output << std::string(2 * (current_depth + 1), ' ');
    output << "[";
    if (child_node.is_directory()) {
      output << "Directory";
    } else {
      output << "Data";
    }

    output << "] ";

    if (child_node.has_name()) {

      output << u16tou8(child_node.name());
    } else {
      output << "ID: " << std::setw(2) << std::setfill('0') << std::dec << child_node.id();
      if (current_depth == 0) {
        output << " - " << to_string(static_cast<RESOURCE_TYPES>(child_node.id()));
      }

      if (current_depth == 2) {
        RESOURCE_LANGS lang        = ResourcesManager::lang_from_id(child_node.id());
        RESOURCE_SUBLANGS sub_lang = ResourcesManager::sublang_from_id(child_node.id());
        output << " - " << to_string(lang) << "/" << to_string(sub_lang);
      }
      output << std::setfill(' ');
    }
    output << std::endl;
    print_tree(child_node, output, current_depth + 1, max_depth);
  }

}

void ResourcesManager::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourcesManager::operator==(const ResourcesManager& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourcesManager::operator!=(const ResourcesManager& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const ResourcesManager& rsrc) {
  os << rsrc.print(3);
  os << std::endl;

  std::set<RESOURCE_TYPES> types = rsrc.get_types_available();
  std::set<RESOURCE_LANGS> langs = rsrc.get_langs_available();
  std::set<RESOURCE_SUBLANGS> sublangs = rsrc.get_sublangs_available();

  if (!types.empty()) {
    std::string types_str = std::accumulate(
        std::begin(types),
        std::end(types), std::string{},
        [] (const std::string& a, RESOURCE_TYPES t) {
         return a.empty() ? to_string(t) : a + " - " + to_string(t);
        });
    os << "Types: " << types_str << std::endl << std::endl;
  }


  if (!langs.empty()) {
    std::string langs_str = std::accumulate(
        std::begin(langs),
        std::end(langs), std::string{},
        [] (const std::string& a, RESOURCE_LANGS l) {
         return a.empty() ? to_string(l) : a + " - " + to_string(l);
        });
    os << "Langs: " << langs_str << std::endl << std::endl;
  }


  if (!sublangs.empty()) {
    std::string sublangs_str = std::accumulate(
        std::begin(sublangs),
        std::end(sublangs), std::string{},
        [] (const std::string& a, RESOURCE_SUBLANGS sl) {
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
    if (auto version = rsrc.version()) {
      os << "Version" << std::endl;
      os << "=======" << std::endl << std::endl;
      os << *version;
      os << std::endl;
    }
  }

  const auto& icons = rsrc.icons();
  for (size_t i = 0; i < icons.size(); ++i) {
    os << "Icon #" << std::dec << i << " : " << std::endl;
    os << icons[i] << std::endl;
  }


  const auto& dialogs = rsrc.dialogs();
  for (size_t i = 0; i < dialogs.size(); ++i) {
    os << "Dialog #" << std::dec << i << " : " << std::endl;
    os << dialogs[i] << std::endl;
  }

  const auto& str_table = rsrc.string_table();
  for (size_t i = 0; i < str_table.size(); ++i) {
    os << fmt::format("StringTable[{}]: {}", i, str_table[i]);
  }
  return os;
}

} // namespace PE
} // namespace LIEF
