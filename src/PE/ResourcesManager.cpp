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

namespace LIEF {
namespace PE {

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

ResourceNode& ResourcesManager::get_node_type(RESOURCE_TYPES type) {
  return const_cast<ResourceNode&>(static_cast<const ResourcesManager*>(this)->get_node_type(type));
}

const ResourceNode& ResourcesManager::get_node_type(RESOURCE_TYPES type) const {
  if (!has_type(type)) {
    throw not_found(std::string("Can't find the node with type '") + to_string(type) + "'");
  }

  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_node = std::find_if(std::begin(nodes), std::end(nodes),
      [type] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == type;
      });

  return *it_node;
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
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_node = std::find_if(std::begin(nodes), std::end(nodes),
      [type] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == type;
      });

  return it_node != std::end(nodes);
}


// Manifest
// ========

bool ResourcesManager::has_manifest() const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_manifest = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::MANIFEST;
      });
  return it_manifest != std::end(nodes);

}

std::string ResourcesManager::manifest() const {
  if (!has_manifest()) {
    LIEF_WARN("No manifest found in the resources");
    return "";
  }

  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_manifest = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::MANIFEST;
      });

  // First level of child nodes
  ResourceNode::it_childs childs_l1 = it_manifest->childs();
  if (childs_l1.size() < 1) {
    LIEF_ERR("Manifest corrupted");
    return "";
  }

  ResourceNode::it_childs childs_l2 = childs_l1[0].childs();
  if (childs_l2.size() < 1) {
    LIEF_ERR("Manifest corrupted");
    return "";
  }
  const ResourceNode& manifest_node = childs_l2[0];
  if (!manifest_node.is_data()) {
    LIEF_WARN("Expecting a Data Node");
    return "";
  }
  const auto& manifest_data = reinterpret_cast<const ResourceData&>(manifest_node);
  const std::vector<uint8_t>& content = manifest_data.content();
  return std::string{std::begin(content), std::end(content)};
}

void ResourcesManager::manifest(const std::string& manifest) {
  if (!has_manifest()) {
    LIEF_ERR("No manifest. We can't create a new one");
    return;
  }

  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_manifest = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::MANIFEST;
      });

  ResourceNode& mnode = *it_manifest;

  auto& data_manifest_node = reinterpret_cast<ResourceData&>(mnode.childs()[0].childs()[0]);
  data_manifest_node.content({std::begin(manifest), std::end(manifest)});
}


// Resource Version
// ================
bool ResourcesManager::has_version() const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_version = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::VERSION;
      });
  return it_version != std::end(nodes);
}

ResourceVersion ResourcesManager::version() const {
  if (!has_version()) {
    throw not_found("Resource version not found");
  }

  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_version = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::VERSION;
      });

  // First level of child nodes
  ResourceNode::it_childs childs_l1 = it_version->childs();
  if (childs_l1.size() < 1) {
    throw not_found("Resource version corrupted");
  }

  ResourceNode::it_childs childs_l2 = childs_l1[0].childs();

  if (childs_l2.size() < 1) {
    throw not_found("Resource version corrupted");
  }

  if (!childs_l2[0].is_data()) {
    throw not_found("Resource version corrupted");
  }

  const auto& version_node = reinterpret_cast<const ResourceData&>(childs_l2[0]);
  const std::vector<uint8_t>& content = version_node.content();
  VectorStream stream{content};
  ResourceVersion version;

  stream.setpos(0);
  // Size of the current "struct"
  auto res_length = stream.read<uint16_t>();
  if (!res_length) {
    LIEF_ERR("Can't read the lenght");
    throw not_found("Resource version corrupted");
  }
  uint16_t length = * res_length;
  LIEF_DEBUG("Lenght of the struct: 0x{:x}", length);

  // Size of the fixed file info struct
  const auto res_value_length = stream.read<uint16_t>();
  if (!res_value_length) {
    LIEF_ERR("Can't read the lenght");
    throw not_found("Resource version corrupted");
  }
  uint16_t value_length = *res_value_length;

  LIEF_DEBUG("Size of the 'FixedFileInfo' struct 0x{:x}", value_length);

  // Type of the data in the version resource
  // 1: Text data
  // 0: Binary data
  auto type = stream.read<uint16_t>();
  if (!type) {
    LIEF_ERR("Can't read version type");
    throw not_found("Resource version corrupted");
  }

  version.type_ = *type;
  if (version.type_ != 0 && version.type_ != 1) {
    LIEF_WARN("\"type\" of the resource version should be equal to 0 or 1 ({:d})", version.type_);
  }


  // Magic key: VS_VERSION_INFO
  auto res_key = stream.read_u16string();
  if (!res_key) {
    LIEF_ERR("Can't read the Magic Key");
    throw not_found("Resource version corrupted");
  }
  std::u16string key = std::move(*res_key);

  if (u16tou8(key, true) != "VS_VERSION_INFO") {
    LIEF_WARN("'key' of the resource version should be equal to 'VS_VERSION_INFO' ({})", u16tou8(key));
  }

  version.key_ = key;
  stream.align(sizeof(uint32_t));

  if (value_length > 0) {
    if (value_length == sizeof(details::pe_resource_fixed_file_info)) {
      auto res_fixed_file_info_header = stream.peek<details::pe_resource_fixed_file_info>();
      if (!res_fixed_file_info_header) {
        LIEF_ERR("Can't read the pe_resource_fixed_file_info structure");
        throw not_found("Resource version corrupted");
      }
      auto fixed_file_info_header = std::move(*res_fixed_file_info_header);
      if (fixed_file_info_header.signature != 0xFEEF04BD) {
        LIEF_WARN("Bad magic value for the Fixed file info structure");
      } else {
        version.fixed_file_info_ = std::make_unique<ResourceFixedFileInfo>(fixed_file_info_header);
      }
    } else {
      LIEF_WARN("The 'value' member contains an unknown structure");
    }
    stream.increment_pos(value_length * sizeof(uint8_t));
  }
  stream.align(sizeof(uint32_t));

  if (!stream.can_read<uint16_t>()) {
    LIEF_DEBUG("There is no entry");
    return version;
  }

  { // First entry
    LIEF_DEBUG("Parsing first entry");
    const auto res_length = stream.peek<uint16_t>();
    if (!res_length) {
      LIEF_ERR("Can't read struct length");
      throw corrupted("corrupted");
    }
    auto length = *res_length;
    LIEF_DEBUG("Length: 0x{:x}", length);

    const size_t start = stream.pos();

    if (length > 0) {
      stream.increment_pos(sizeof(uint16_t));

      auto res_struct_length = stream.read<uint16_t>();
      if (!res_struct_length) {
        throw corrupted("corrupted");
      }
      auto struct_length = *res_struct_length;
      LIEF_DEBUG("Length of the struct: 0x{:x}", struct_length);

      const auto res_type = stream.read<uint16_t>();
      if (!res_type) {
        LIEF_ERR("Can't read type");
        throw corrupted("corrupted");
      }
      auto type = *res_type;
      LIEF_DEBUG("Type of the struct: {:d}", type);

      auto res_key = stream.read_u16string();
      if (!res_key) {
        LIEF_ERR("Can't read the magic key string");
        throw corrupted("corrupted");
      }

      std::u16string key = std::move(*res_key);
      const std::string& u8_key = u16tou8(key, /* remove null char */ true);
      LIEF_DEBUG("First entry (key) {}", u8_key);
      if (u8_key == "StringFileInfo") {
        try {
          version.string_file_info_ = get_string_file_info(stream, type, key, start, length);
        } catch (const LIEF::exception& e) {
          LIEF_ERR("{}", e.what());
        }
      }
      else if (u8_key == "VarFileInfo") {
        try {
          version.var_file_info_ = get_var_file_info(stream, type, key, start, length);
        } catch (const LIEF::exception& e) {
          LIEF_ERR("{}", e.what());
        }
      }
      else {
        LIEF_WARN("Unknown key: {}", u8_key);
      }
    }
  }


  { // Second entry

    LIEF_DEBUG("Parsing second entry");
    auto res_length = stream.peek<uint16_t>();
    if (!res_length) {
      LIEF_ERR("Can't read the length");
      throw corrupted("corrupted");
    }

    auto length = *res_length;
    LIEF_DEBUG("Length: 0x{:x}", length);

    const size_t start = stream.pos();

    if (length > 0) {
      stream.increment_pos(sizeof(uint16_t));
      const auto struct_length = stream.read<uint16_t>();

      if (!struct_length) {
        LIEF_ERR("Can't read struct_length");
        throw corrupted("corrupted");
      }
      LIEF_DEBUG("Lenght of the struct: 0x{:x}", *struct_length);

      auto res_type = stream.read<uint16_t>();
      if (!res_type) {
        LIEF_ERR("Can't read the type");
        throw corrupted("corrupted");
      }
      auto type = *res_type;
      LIEF_DEBUG("Type of the struct: {:d}", type);

      auto res_key = stream.read_u16string();
      if (!res_key) {
        LIEF_ERR("Can't read the magic key");
        throw corrupted("corrupted");
      }
      std::u16string key = std::move(*res_key);
      const std::string& u8_key = u16tou8(key);
      stream.align(sizeof(uint32_t));

      LIEF_DEBUG("Second entry (key) {}", u8_key);
      if (u8_key == "StringFileInfo") {
        try {
          version.string_file_info_ = get_string_file_info(stream, type, key, start, length);
        } catch (const LIEF::exception& e) {
          LIEF_ERR("{}", e.what());
        }
      }
      else if (u8_key == "VarFileInfo") {
        try {
          version.var_file_info_ = get_var_file_info(stream, type, key, start, length);
        } catch (const LIEF::exception& e) {
          LIEF_ERR("{}", e.what());
        }
      }
      else {
        LIEF_WARN("Unknown key: {}", u8_key);
      }
    }
  }

  return version;
}


std::unique_ptr<ResourceStringFileInfo> ResourcesManager::get_string_file_info(const VectorStream& stream,
            uint16_t type, std::u16string key, size_t start, size_t struct_length) const {
  LIEF_DEBUG("Getting StringFileInfo object");

  // String File Info
  // ================
  auto string_file_info = std::make_unique<ResourceStringFileInfo>();

  string_file_info->type_ = type;
  string_file_info->key_  = std::move(key);


  // Parse 'StringTable' childs
  // ==========================
  LIEF_DEBUG("Parsing 'StringTable' struct");
  const size_t end_string_stable = start + struct_length * sizeof(uint8_t);

  while (stream.pos() < end_string_stable) {
    LangCodeItem lang_code_item;
    auto res_string_table_length = stream.peek<uint16_t>();
    if (!res_string_table_length) {
      LIEF_ERR("Can't read the StringTable length");
      throw corrupted("corrupted");
    }

    auto string_table_length = *res_string_table_length;

    // End of the structure including childs
    const uint64_t end_offset = stream.pos() + string_table_length * sizeof(uint8_t);
    stream.increment_pos(sizeof(uint16_t));

    auto stringtable_value_length = stream.read<uint16_t>();
    if (!stringtable_value_length) {
      LIEF_ERR("Can't read stringtable_value_length");
      throw corrupted("corrupted");
    }

    LIEF_DEBUG("Value length: {:d} (should be 0)", *stringtable_value_length);

    auto stringtable_type = stream.read<uint16_t>();

    if (!stringtable_type) {
      LIEF_ERR("Can't read stringtable_value_length");
      throw corrupted("corrupted");
    }

    LIEF_DEBUG("Type: {:d}", *stringtable_type);

    // 1: Text data
    // 0: Binary data
    if (type != 0 && type != 1) {
      LIEF_WARN("'type' of the StringTable should be equal to 0 or 1 ({:d})", type);
    }
    lang_code_item.type_ = type;


    auto res_key = stream.read_u16string();
    if (!res_key) {
      LIEF_ERR("Can't read the magic key");
      throw corrupted("corrupted");
    }
    std::u16string key = std::move(*res_key);

    lang_code_item.key_ = key;
    LIEF_DEBUG("ID: {}", u16tou8(key));

    std::string key_str = u16tou8(key);

    if (key.length() != 8) {
      LIEF_ERR("Corrupted key ({} {})", u16tou8(key), key_str);
    } else {
      const std::string& chunk_1 = u16tou8(key.substr(0, 4));
      const std::string& chunk_2 = u16tou8(key.substr(4, 8));
      uint64_t lang_id = 0;
      uint64_t code_page = 0;
      if (is_hex_number(chunk_1)) {
        lang_id = std::stoul(chunk_1, nullptr, 16);
      } else {
        LIEF_WARN("Invalid hex-string for Lang ID: '{}'", chunk_1);
      }

      if (is_hex_number(chunk_2)) {
        code_page = std::stoul(chunk_2, nullptr, 16);
      } else {
        LIEF_WARN("Invalid hex-string for Code page: '{}'", chunk_2);
      }

      LIEF_DEBUG("Lang ID: {:d}", lang_id);
      LIEF_DEBUG("Code page: 0x{:x}", code_page);
    }

    stream.align(sizeof(uint32_t));

    // Parse 'String'
    // ==============
    while (stream.pos() < end_offset) {
      const size_t string_offset = stream.pos();

      auto res_string_length = stream.read<uint16_t>();
      if (!res_string_length) {
        LIEF_ERR("Can't read string_length");
        throw corrupted("corrupted");
      }

      auto string_length = *res_string_length;
      LIEF_DEBUG("Length of the 'string' struct: 0x{:x}", string_length);

      auto res_string_value_length = stream.read<uint16_t>();
      if (!res_string_table_length) {
        LIEF_ERR("Can't read res_string_table_length");
        throw corrupted("corrupted");
      }
      auto string_value_length = *res_string_value_length;
      LIEF_DEBUG("Size of the 'value' member: 0x{:x}", string_value_length);

      auto res_string_type = stream.read<uint16_t>();
      if (!res_string_type) {
        LIEF_ERR("Can't read res_string_type");
        throw corrupted("corrupted");
      }
      auto string_type = *res_string_type;
      LIEF_DEBUG("Type of the 'string' struct: {:d}", string_type);

      auto res_key = stream.read_u16string();
      if (!res_key) {
        LIEF_ERR("Can't read the key");
        throw corrupted("corrupted");
      }

      std::u16string key = std::move(*res_key);
      LIEF_DEBUG("Key: {}", u16tou8(key));
      stream.align(sizeof(uint32_t));

      std::u16string value;
      if (string_value_length > 0 && stream.pos() < string_offset + string_length) {
        auto res_val = stream.read_u16string();
        if (res_val) {
          value = std::move(*res_val);
        } else {
          LIEF_ERR("Can't read string value");
        }
        LIEF_DEBUG("Value: {}", u16tou8(value));
      } else {
        LIEF_DEBUG("Value: (empty)");
      }

      const size_t expected_end = string_offset + string_length;

      if (stream.pos() < expected_end && expected_end < end_offset) {
        stream.setpos(expected_end);
      }
      stream.align(sizeof(uint32_t));
      lang_code_item.items_.emplace(key, value);
    }
    string_file_info->childs_.push_back(std::move(lang_code_item));
  }
  //stream.setpos(end_string_stable);
  return string_file_info;
}


std::unique_ptr<ResourceVarFileInfo> ResourcesManager::get_var_file_info(const VectorStream& stream,
    uint16_t type, std::u16string key, size_t start, size_t struct_length) const {
  LIEF_DEBUG("Getting VarFileInfo object");
  // Var file info
  // =============
  auto var_file_info = std::make_unique<ResourceVarFileInfo>();

  var_file_info->type_ = type;
  var_file_info->key_  = std::move(key);

  // Parse 'Var' childs
  // ==================
  LIEF_DEBUG("Parsing 'Var' childs");
  const size_t end_var_file_info = start + struct_length * sizeof(uint8_t);
  while (stream.pos() < end_var_file_info) {
    auto var_length = stream.read<uint16_t>();
    if (!var_length) {
      LIEF_ERR("Can't read var_length");
      return nullptr;
    }
    LIEF_DEBUG("Size of the 'Var' struct: 0x{:d}", *var_length);

    auto var_value_length = stream.read<uint16_t>();

    if (!var_value_length) {
      LIEF_ERR("Can't read var_value_length");
      return nullptr;
    }
    LIEF_DEBUG("Size of the 'Value' member: 0x{:x}", *var_value_length);

    auto var_type = stream.read<uint16_t>();
    if (!var_type) {
      LIEF_ERR("Can't read var_type");
      return nullptr;
    }
    LIEF_DEBUG("Type: {:d}", *var_type);

    auto res_key = stream.read_u16string();
    if (!res_key) {
      LIEF_ERR("Can't read key");
      return nullptr;
    }
    std::u16string res = std::move(*res_key);
    if (u16tou8(key) != "Translation") {
      LIEF_WARN("'key' of the var key should be equal to 'Translation' ({})", u16tou8(key));
    }
    stream.align(sizeof(uint32_t));

    const size_t nb_items = *var_value_length / sizeof(uint32_t);
    const auto *value_array = stream.read_array<uint32_t>(nb_items);
    if (value_array == nullptr) {
      LIEF_ERR("Unable to read items");
      return var_file_info;
    }

    for (size_t i = 0; i < nb_items; ++i) {
      LIEF_DEBUG("item[{:02d} = 0x{:x}", i, value_array[i]);
      var_file_info->translations_.push_back(value_array[i]);
    }
  }
  stream.setpos(end_var_file_info);
  return var_file_info;
}

// Icons
// =====

bool ResourcesManager::has_icons() const {

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
    return false;
  }

  if (it_grp_icon == std::end(nodes)) {
    return false;
  }

  return true;

}

std::vector<ResourceIcon> ResourcesManager::icons() const {

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
    return {};
  }

  if (it_grp_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::GROUP_ICON));
    return {};
  }

  std::vector<ResourceIcon> icons;
  for (const ResourceNode& grp_icon_lvl2 : it_grp_icon->childs()) {
    for (const ResourceNode& grp_icon_lvl3 : grp_icon_lvl2.childs()) {
      if (!grp_icon_lvl3.is_data()) {
        LIEF_WARN("Expecting a data node");
        continue;
      }
      const auto* icon_group_node = reinterpret_cast<const ResourceData*>(&grp_icon_lvl3);
      if (icon_group_node == nullptr) {
        LIEF_WARN("Group icon node is null");
        continue;
      }

      const std::vector<uint8_t>& icon_group_content = icon_group_node->content();
      if (icon_group_content.empty()) {
        LIEF_WARN("Group icon is empty");
        continue;
      }

      const auto* group_icon_header = reinterpret_cast<const details::pe_resource_icon_dir*>(icon_group_content.data());

      LIEF_DEBUG("Number of icons: {:d}", static_cast<uint32_t>(group_icon_header->count));
      LIEF_DEBUG("Type: {:d}", static_cast<uint32_t>(group_icon_header->type));

      // Some checks
      if (group_icon_header->type != 1) {
        LIEF_ERR("Group icon type should be equal to 1 (vs {})", group_icon_header->type);
        return {};
      }
      const uint64_t icn_count = group_icon_header->count * sizeof(details::pe_resource_icon_group) +
                                 sizeof(details::pe_resource_icon_dir);
      if (icn_count > icon_group_content.size()) {
        LIEF_ERR("The Number of icons seems corrupted ({} entries)", group_icon_header->count);
        return {};
      }

      for (size_t i = 0; i < group_icon_header->count; ++i) {
        const auto* icon_header = reinterpret_cast<const details::pe_resource_icon_group*>(
            icon_group_content.data() +
            sizeof(details::pe_resource_icon_dir) +
            i * sizeof(details::pe_resource_icon_group));

        const uint32_t id = icon_header->ID;

        ResourceIcon icon{*icon_header};
        icon.lang_    = ResourcesManager::lang_from_id(grp_icon_lvl3.id());
        icon.sublang_ = ResourcesManager::sublang_from_id(grp_icon_lvl3.id());

        ResourceNode::it_childs sub_nodes_icons = it_icon->childs();

        const auto it_icon_dir = std::find_if(std::begin(sub_nodes_icons), std::end(sub_nodes_icons),
            [&id] (const ResourceNode& node) {
              return node.id() == id;
            });

        if (it_icon_dir == std::end(sub_nodes_icons)) {
          LIEF_WARN("Unable to find the icon associated with id: {:d}", id);
          continue;
        }
        ResourceNode::it_childs icons_childs = it_icon_dir->childs();
        if (icons_childs.size() < 1) {
          LIEF_WARN("Resources nodes loooks corrupted");
          continue;
        }
        const ResourceNode& icon_node = icons_childs[0];
        if (!icon_node.is_data()) {
          LIEF_WARN("Expecting a Data node but found a Directory node");
          continue;
        }
        const std::vector<uint8_t>& pixels = reinterpret_cast<const ResourceData*>(&icons_childs[0])->content();
        icon.pixels_ = pixels;

        icons.push_back(icon);
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
  it_icon->sort_by_id();
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
  it_icon->sort_by_id();
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
std::vector<ResourceDialog> ResourcesManager::dialogs() const {
  if (!has_dialogs()) {
    return {};
  }
  std::vector<ResourceDialog> dialogs;
  const ResourceNode& dialog_node = get_node_type(RESOURCE_TYPES::DIALOG);
  if (!dialog_node.is_directory()) {
    LIEF_WARN("Dialog node corrupted");
    return {};
  }
  const auto& dialog_dir = reinterpret_cast<const ResourceDirectory&>(dialog_node);

  ResourceNode::it_const_childs nodes = dialog_dir.childs();
  for (size_t i = 0; i < nodes.size(); ++i) {
    if (!nodes[i].is_directory()) {
      LIEF_WARN("Dialog node corrupted");
      continue;
    }

    const auto& dialog = reinterpret_cast<const ResourceDirectory&>(nodes[i]);
    ResourceNode::it_const_childs langs = dialog.childs();

    for (size_t j = 0; j < langs.size(); ++j) {
      if (!langs[j].is_data()) {
        LIEF_WARN("Dialog node corrupted");
        continue;
      }
      const auto& data_node = reinterpret_cast<const ResourceData&>(langs[j]);
      const std::vector<uint8_t>& content = data_node.content();
      VectorStream stream{content};
      stream.setpos(0);

      if (content.size() < std::min(sizeof(details::pe_dialog_template_ext), sizeof(details::pe_dialog_template))) {
        LIEF_WARN("Dialog is corrupted!");
        return {};
      }

      if (content[2] == 0xFF && content[3] == 0xFF) {

        if (content.size() < sizeof(details::pe_dialog_template_ext)) {
          LIEF_WARN("Dialog is corrupted!");
          return {};
        }

        auto res_dialog_template_ext = stream.read<details::pe_dialog_template_ext>();
        if (!res_dialog_template_ext) {
          LIEF_ERR("Can't read pe_dialog_template_ext");
          return {};
        }
        auto raw_dialog_template_ext = *res_dialog_template_ext;
        ResourceDialog new_dialog = raw_dialog_template_ext;
        new_dialog.lang(ResourcesManager::lang_from_id(data_node.id()));
        new_dialog.sub_lang(ResourcesManager::sublang_from_id(data_node.id()));

        // Menu
        // ====
        auto res_menu_hint = stream.read<uint16_t>();
        if (!res_menu_hint) {
          LIEF_ERR("Can't read menu_hint");
          return {};
        }
        switch(*res_menu_hint) {
          case 0x0000:
            {
              LIEF_DEBUG("Dialog has not menu");
              break;
            }

          case 0xFFFF:
            {
              auto res_menu_ordinal = stream.read<uint16_t>();
              if (!res_menu_ordinal) {
                LIEF_ERR("Error while reading menu_ordinal");
                return {};
              }
              auto menu_ordinal = *res_menu_ordinal;
              LIEF_DEBUG("Menu uses ordinal number {:d}", menu_ordinal);
              break;
            }

          default:
            {
              LIEF_DEBUG("Menu uses unicode string");
              auto res_menu_name = stream.read_u16string();
              if (!res_menu_name) {
                LIEF_ERR("Error while reading menu unicode string");
                return {};
              }
            }
        }


        // Window Class
        // ============
        stream.align(sizeof(uint16_t));

        auto window_class_hint = stream.read<uint16_t>();
        if (!window_class_hint) {
          LIEF_ERR("Can't read window_class_hint");
          return {};
        }

        switch (*window_class_hint) {
          case 0x0000:
            {
              LIEF_DEBUG("Windows class uses predefined dialog box");
              break;
            }

          case 0xFFFF:
            {
              auto windows_class_ordinal = stream.read<uint16_t>();
              if (!windows_class_ordinal) {
                LIEF_ERR("Can't read windows_class_ordinal");
                return {};
              }
              LIEF_DEBUG("Windows class uses ordinal number {:d}", *windows_class_ordinal);
              break;
            }

          default:
            {
              LIEF_DEBUG("Windows class uses unicode string");
              auto res_window_class_name = stream.read_u16string();
              if (!res_window_class_name) {
                LIEF_ERR("Can't read unicode string associated with the window class");
                return {};
              }
            }
        }

        // Title
        // =====
        stream.align(sizeof(uint16_t));
        LIEF_DEBUG("Title offset: 0x{:x}", stream.pos());
        auto res_title = stream.read_u16string();
        if (!res_title) {
          LIEF_ERR("Can't read the title");
          return {};
        }
        new_dialog.title_ = std::move(*res_title);

        // 2nd part
        // ========
        const std::set<DIALOG_BOX_STYLES>& dialogbox_styles = new_dialog.dialogbox_style_list();
        if (dialogbox_styles.count(DIALOG_BOX_STYLES::DS_SHELLFONT) > 0 || dialogbox_styles.count(DIALOG_BOX_STYLES::DS_SETFONT) > 0) {
          auto point_size = stream.read<uint16_t>();
          if (!point_size) {
            LIEF_ERR("Can't read the point size");
            return {};
          }
          new_dialog.point_size_ = *point_size;

          const auto weight = stream.read<uint16_t>();
          if (!weight) {
            LIEF_ERR("Can't read the wight");
            return {};
          }
          new_dialog.weight_ = *weight;

          auto is_italic = stream.read<uint8_t>();
          if (!is_italic) {
            LIEF_ERR("Can't read italic boolean value");
            return {};
          }
          new_dialog.italic_ = static_cast<bool>(*is_italic);

          auto charset = stream.read<uint8_t>();
          if (!charset) {
            LIEF_ERR("Can't read charset boolean value");
            return {};
          }
          new_dialog.charset_ = *charset;
          auto res_typeface = stream.read_u16string();
          if (!res_typeface) {
            LIEF_ERR("Can't read the typeface");
            return {};
          }
          new_dialog.typeface_ = std::move(*res_typeface);
        }

        LIEF_DEBUG("Offset to the items: 0x{:x}", stream.pos());
        LIEF_DEBUG("\n\n####### Items #######\n");

        // Items
        // =====
        for (size_t i = 0; i < raw_dialog_template_ext.nbof_items; ++i) {
          stream.align(sizeof(uint32_t));
          LIEF_DEBUG("item[{:02d}] offset: 0x{:x}", i, stream.pos());
          ResourceDialogItem dialog_item;

          if (new_dialog.is_extended()) {
            auto item_header = stream.read<details::pe_dialog_item_template_ext>();
            if (!item_header) {
              LIEF_ERR("Can't read item header");
              break;
            }
            dialog_item = ResourceDialogItem{*item_header};
            LIEF_DEBUG("Item ID: {:d}", item_header->id);
          } else {
            auto item_header = stream.read<details::pe_dialog_item_template>();
            if (!item_header) {
              LIEF_ERR("Can't read item header");
              break;
            }
            new_dialog.items_.emplace_back(*item_header);
            continue;
          }

          // window class
          // ------------
          stream.align(sizeof(uint32_t));
          auto window_class_hint = stream.peek<uint16_t>();
          if (!window_class_hint) {
            LIEF_ERR("Can't read window_class_hint");
            return {};
          }

          if (*window_class_hint == 0xFFFF) {
            stream.increment_pos(sizeof(uint16_t));
            auto windows_class_ordinal = stream.read<uint16_t>();
            if (!windows_class_ordinal) {
              LIEF_ERR("Can't read windows_class_ordinal");
              return {};
            }
            LIEF_DEBUG("Windows class uses ordinal number {:d}", *windows_class_ordinal);
          } else {
            LIEF_DEBUG("Windows class uses unicode string");
            auto window_class_name = stream.read_u16string();
            if (!window_class_name) {
              LIEF_ERR("Can't read window_class_name");
              return {};
            }
            LIEF_DEBUG("{}", u16tou8(*window_class_name));
          }

          // Title
          // -----
          auto title_hint = stream.peek<uint16_t>();
          if (!title_hint) {
            LIEF_ERR("Can't read title_hint");
            return {};
          }

          if (*title_hint == 0xFFFF) {
            stream.increment_pos(sizeof(uint16_t));
            auto title_ordinal = stream.read<uint16_t>();
            if (!title_ordinal) {
              LIEF_ERR("Can't read title_ordinal");
              return {};
            }
            LIEF_DEBUG("Title uses ordinal number {:d}", *title_ordinal);
          } else {
            auto title_name = stream.read_u16string();
            if (!title_name) {
              LIEF_ERR("Can't read title_name");
              return {};
            }
            LIEF_DEBUG("Title uses unicode string: '{}'", u16tou8(*title_name));
            dialog_item.title_ = std::move(*title_name);
          }

          // Extra count
          // -----------
          auto extra_count = stream.read<uint16_t>();
          if (!extra_count) {
            LIEF_ERR("Can't read extra_count");
            return {};
          }
          LIEF_DEBUG("Extra count: 0x{:x}", *extra_count);
          dialog_item.extra_count_ = *extra_count;
          stream.increment_pos(*extra_count * sizeof(uint8_t));
          new_dialog.items_.push_back(std::move(dialog_item));
        }

        dialogs.push_back(std::move(new_dialog));
      }
    }
  }
  return dialogs;
}


bool ResourcesManager::has_dialogs() const {
  return has_type(RESOURCE_TYPES::DIALOG);
}

// String table entry
std::vector<ResourceStringTable> ResourcesManager::string_table() const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_string_table = std::find_if(std::begin(nodes), std::end(nodes),
    [] (const ResourceNode& node) {
      return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::STRING;
    }
  );

  if (it_string_table == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::STRING));
    return {};
  }

  std::vector<ResourceStringTable> string_table;
  for (const ResourceNode& child_l1 : it_string_table->childs()) {

    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_WARN("String node corrupted");
        continue;
      }
      const auto& string_table_node = reinterpret_cast<const ResourceData&>(child_l2);

      const std::vector<uint8_t>& content = string_table_node.content();
      if (content.empty()) {
        LIEF_ERR("String table content is empty");
        continue;
      }

      const auto content_size = content.size();
      VectorStream stream{content};
      stream.setpos(0);
      LIEF_DEBUG("Will parse content with the size {}", content_size);
      while (stream.pos() < content_size) {
        auto res_len = stream.read<uint16_t>();
        if (!res_len) {
          break;
        }
        auto len = *res_len;
        if (len > 0 && ((len * 2) < content_size)) {
          auto name = stream.read_u16string(len);
          if (!name) {
            LIEF_ERR("Can't read name");
            break;
          }
          string_table.emplace_back(ResourceStringTable(len, std::move(*name)));
        }
      }
    }

  }

  return string_table;
}

bool ResourcesManager::has_string_table() const {
  return has_type(RESOURCE_TYPES::STRING);
}

std::vector<std::string> ResourcesManager::html() const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_html = std::find_if(std::begin(nodes), std::end(nodes),
    [] (const ResourceNode& node) {
      return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::HTML;
    }
  );

  if (it_html == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::HTML));
    return {};
  }

  std::vector<std::string> html;
  for (const ResourceNode& child_l1 : it_html->childs()) {
    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_ERR("html node corrupted");
        continue;
      }
      const auto& html_node = reinterpret_cast<const ResourceData&>(child_l2);

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
  return has_type(RESOURCE_TYPES::HTML);
}

bool ResourcesManager::has_accelerator() const {
  return has_type(RESOURCE_TYPES::ACCELERATOR);
}

std::vector<ResourceAccelerator> ResourcesManager::accelerator() const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_accelerator = std::find_if(std::begin(nodes), std::end(nodes),
    [] (const ResourceNode& node) {
      return static_cast<RESOURCE_TYPES>(node.id()) == RESOURCE_TYPES::ACCELERATOR;
    }
  );

  if (it_accelerator == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(RESOURCE_TYPES::ACCELERATOR));
    return {};
  }

  std::vector<ResourceAccelerator> accelerator;
  for (const ResourceNode& child_l1 : it_accelerator->childs()) {
    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_ERR("Accelerator node corrupted");
        continue;
      }
      const auto& accelerator_node = reinterpret_cast<const ResourceData&>(child_l2);

      const std::vector<uint8_t>& content = accelerator_node.content();
      if (content.empty()) {
        LIEF_ERR("Accelerator content is empty");
        continue;
      }

      VectorStream stream{content};
      while (stream.can_read<details::pe_resource_acceltableentry>()) {
        auto entry = stream.read<details::pe_resource_acceltableentry>();
        if (!entry) {
          LIEF_ERR("Can't read pe_resource_acceltableentry");
          break;
        }
        accelerator.emplace_back(ResourceAccelerator(std::move(*entry)));
      }
      if (!accelerator.empty()) {
        ResourceAccelerator& acc = accelerator.back();
        if ((acc.flags() & int16_t(ACCELERATOR_FLAGS::END)) != int16_t(ACCELERATOR_FLAGS::END)) {
          LIEF_ERR("Accelerator resource may be corrupted");
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
    os << "Version" << std::endl;
    os << "=======" << std::endl << std::endl;
    try {
      os << rsrc.version();
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
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
      LIEF_WARN("{}", e.what());
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
      LIEF_WARN("{}", e.what());
    }
  }


  return os;
}

} // namespace PE
} // namespace LIEF
