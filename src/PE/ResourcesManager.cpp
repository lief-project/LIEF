/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "LIEF/Visitor.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include "PE/ResourcesParser.hpp"
#include "PE/Structures.hpp"

#include "LIEF/BinaryStream/SpanStream.hpp"

#include "frozen.hpp"
#include "logging.hpp"
#include "internal_utils.hpp"
#include "fmt_formatter.hpp"

FMT_FORMATTER(LIEF::PE::ResourcesManager::TYPE, LIEF::PE::to_string);

namespace LIEF {
namespace PE {

static constexpr auto RESOURCE_TYPES = {
  ResourcesManager::TYPE::CURSOR,         ResourcesManager::TYPE::BITMAP,
  ResourcesManager::TYPE::ICON,           ResourcesManager::TYPE::MENU,
  ResourcesManager::TYPE::DIALOG,         ResourcesManager::TYPE::STRING,
  ResourcesManager::TYPE::FONTDIR,        ResourcesManager::TYPE::FONT,
  ResourcesManager::TYPE::ACCELERATOR,    ResourcesManager::TYPE::RCDATA,
  ResourcesManager::TYPE::MESSAGETABLE,   ResourcesManager::TYPE::GROUP_CURSOR,
  ResourcesManager::TYPE::GROUP_ICON,     ResourcesManager::TYPE::VERSION,
  ResourcesManager::TYPE::DLGINCLUDE,     ResourcesManager::TYPE::PLUGPLAY,
  ResourcesManager::TYPE::VXD,            ResourcesManager::TYPE::ANICURSOR,
  ResourcesManager::TYPE::ANIICON,        ResourcesManager::TYPE::HTML,
  ResourcesManager::TYPE::MANIFEST,
};

ResourceNode* ResourcesManager::get_node_type(ResourcesManager::TYPE type) {
  return const_cast<ResourceNode*>(static_cast<const ResourcesManager*>(this)->get_node_type(type));
}

const ResourceNode* ResourcesManager::get_node_type(ResourcesManager::TYPE type) const {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_node = std::find_if(std::begin(nodes), std::end(nodes),
      [type] (const ResourceNode& node) {
        return ResourcesManager::TYPE(node.id()) == type;
      });

  if (it_node == std::end(nodes)) {
    return nullptr;
  }

  return &*it_node;
}

std::vector<ResourcesManager::TYPE> ResourcesManager::get_types() const {
  std::vector<ResourcesManager::TYPE> types;
  for (const ResourceNode& node : resources_->childs()) {
    const auto it = std::find_if(std::begin(RESOURCE_TYPES), std::end(RESOURCE_TYPES),
        [&node] (ResourcesManager::TYPE t) {
          return t == ResourcesManager::TYPE(node.id());
        });

    if (it != std::end(RESOURCE_TYPES)) {
      types.push_back(*it);
    }
  }
  return types;
}

std::string ResourcesManager::manifest() const {
  const ResourceNode* root_node = get_node_type(TYPE::MANIFEST);
  if (root_node == nullptr) {
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
  span<const uint8_t> content = manifest_data.content();
  return std::string{std::begin(content), std::end(content)};
}

void ResourcesManager::manifest(const std::string& manifest) {
  if (ResourceNode* manifest_node = get_node_type(TYPE::MANIFEST)) {
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
result<ResourceVersion> ResourcesManager::version() const {
  const ResourceNode* root_node = get_node_type(TYPE::VERSION);
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
  span<const uint8_t> content = version_node.content();

  ResourceVersion version;
  SpanStream stream(content);
  if (auto version = ResourcesParser::parse_vs_versioninfo(stream)) {
    return *version;
  }
  return make_error_code(lief_errors::corrupted);
}

// Icons
// =====

ResourcesManager::it_const_icons ResourcesManager::icons() const {
  std::vector<ResourceIcon> icons;
  const ResourceNode* root_icon     = get_node_type(TYPE::ICON);
  const ResourceNode* root_grp_icon = get_node_type(TYPE::GROUP_ICON);
  if (root_icon == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::ICON));
    return icons;
  }

  if (root_grp_icon == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::GROUP_ICON));
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

      span<const uint8_t> icon_group_content = icon_group_node.content();
      if (icon_group_content.empty()) {
        LIEF_INFO("Group icon is empty");
        continue;
      }

      SpanStream stream(icon_group_content);
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
        span<const uint8_t> pixels = static_cast<const ResourceData&>(icon_node).content();
        icon.pixels_ = std::vector<uint8_t>(std::begin(pixels), std::end(pixels));
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
        return TYPE(node.id()) == TYPE::ICON;
      });


  const auto it_grp_icon = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return TYPE(node.id()) == TYPE::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::ICON));
    return;
  }

  if (it_grp_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::GROUP_ICON));
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
  span<uint8_t> icon_group_content = icon_group_node.content();
  std::vector<uint8_t> buffer(icon_group_content.begin(), icon_group_content.end());

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

  const auto pos = std::begin(buffer) +
                   sizeof(details::pe_resource_icon_dir) + group_icon_header->count * sizeof(details::pe_resource_icon_group);

  buffer.insert(pos, reinterpret_cast<uint8_t*>(&new_icon_header),
                     reinterpret_cast<uint8_t*>(&new_icon_header) + sizeof(details::pe_resource_icon_group));

  group_icon_header->count++;

  icon_group_node.content(std::move(buffer));

  // Add to the ICON list
  ResourceDirectory new_icon_dir_node;
  new_icon_dir_node.id(new_id);

  ResourceData new_icon_data_node{as_vector(icon.pixels()), 0};
  new_icon_data_node.id(static_cast<int>(icon.sublang()) << 10 | static_cast<int>(icon.lang()));
  new_icon_dir_node.add_child(new_icon_data_node);

  it_icon->add_child(new_icon_dir_node);
}


void ResourcesManager::change_icon(const ResourceIcon& original, const ResourceIcon& newone) {
  ResourceNode::it_childs nodes = resources_->childs();
  const auto it_icon = std::find_if(std::begin(nodes), std::end(nodes),
      [] (const ResourceNode& node) {
        return TYPE(node.id()) == TYPE::ICON;
      });


  const auto it_grp_icon = std::find_if(std::begin(nodes),
      std::end(nodes),
      [] (const ResourceNode& node) {
        return TYPE(node.id()) == TYPE::GROUP_ICON;
      });

  if (it_icon == std::end(nodes)) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::ICON));
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

      span<uint8_t> icon_group_content = icon_group_node.content();
      std::vector<uint8_t> buffer = std::vector<uint8_t>(icon_group_content.begin(), icon_group_content.end());

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
      icon_group_node.content(std::move(buffer));
    }
  }

  // 2. Update icons
  // ---------------
  it_icon->delete_child(original.id());
  ResourceDirectory new_icon_dir_node;
  new_icon_dir_node.id(newone.id());

  ResourceData new_icon_data_node{as_vector(newone.pixels()), 0};
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

  const ResourceNode* dialog_node = get_node_type(TYPE::DIALOG);
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
      span<const uint8_t> content = data_node.content();
      SpanStream stream(content);
      if (!ResourcesParser::parse_dialogs(dialogs, data_node, stream)) {
        LIEF_INFO("Parsing resources dialogs #{}->{} finished with errors", i, j);
      }
    }
  }
  return dialogs;
}


// String table entry
ResourcesManager::it_const_strings_table ResourcesManager::string_table() const {
  std::vector<ResourceStringTable> string_table;
  const ResourceNode* root_node = get_node_type(TYPE::STRING);
  if (root_node == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::STRING));
    return string_table;
  }

  for (const ResourceNode& child_l1 : root_node->childs()) {

    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_WARN("Expecting a data not for the string node id {}", child_l2.id());
        continue;
      }
      const auto& string_table_node = static_cast<const ResourceData&>(child_l2);
      span<const uint8_t> content = string_table_node.content();
      if (content.empty()) {
        LIEF_ERR("String table content is empty");
        continue;
      }

      SpanStream stream(content);
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

std::vector<std::string> ResourcesManager::html() const {
  const ResourceNode* root_node = get_node_type(TYPE::HTML);
  if (root_node == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::HTML));
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

      span<const uint8_t> content = html_node.content();
      if (content.empty()) {
        LIEF_ERR("html content is empty");
        continue;
      }
      html.push_back(std::string{std::begin(content), std::end(content)});
    }
  }

  return html;
}

ResourcesManager::it_const_accelerators ResourcesManager::accelerator() const {
  std::vector<ResourceAccelerator> accelerator;
  const ResourceNode* root_node = get_node_type(TYPE::ACCELERATOR);
  if (root_node == nullptr) {
    LIEF_ERR("Missing '{}' entry", to_string(TYPE::ACCELERATOR));
    return accelerator;
  }

  for (const ResourceNode& child_l1 : root_node->childs()) {
    for (const ResourceNode& child_l2 : child_l1.childs()) {
      if (!child_l2.is_data()) {
        LIEF_ERR("Expecting a Data node for node id:: {}", child_l2.id());
        continue;
      }
      const auto& accelerator_node = static_cast<const ResourceData&>(child_l2);

      span<const uint8_t> content = accelerator_node.content();
      if (content.empty()) {
        LIEF_INFO("Accelerator content is empty");
        continue;
      }

      SpanStream stream(content);
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
    std::string space(2 * (current_depth + 1), ' ');
    std::string type = child_node.is_directory() ? "Directory" : "Data";
    output << fmt::format("{}[{}]", space, type);
    if (child_node.has_name()) {
      output << u16tou8(child_node.name());
    } else {
      output << fmt::format("ID: {:02d}", child_node.id());
      if (current_depth == 0) {
        output << fmt::format(" - {}",  to_string(TYPE(child_node.id())));
      }

      if (current_depth == 2) {
        uint32_t lang        = ResourcesManager::lang_from_id(child_node.id());
        uint32_t sub_lang = ResourcesManager::sublang_from_id(child_node.id());
        output << fmt::format(" - Lang: 0x{:02x} / Sublang: 0x{:02x}", lang, sub_lang);
      }
    }
    output << '\n';
    print_tree(child_node, output, current_depth + 1, max_depth);
  }
}

void ResourcesManager::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const ResourcesManager& rsrc) {
  os << rsrc.print(3) << '\n';

  std::vector<ResourcesManager::TYPE> types = rsrc.get_types();

  if (!types.empty()) {
    os << fmt::format("Types: {}\n", types);
  }

  if (const std::string& manifest = rsrc.manifest(); !manifest.empty()) {
    os << fmt::format("Manifest:\n{}\n", manifest);
  }

  if (auto version = rsrc.version()) {
    os << fmt::format("Version:\n{}\n", to_string(*version));
  }

  const auto& icons = rsrc.icons();
  for (size_t i = 0; i < icons.size(); ++i) {
    os << fmt::format("Icon #{:02d}:\n{}\n", i, to_string(icons[i]));
  }

  const auto& dialogs = rsrc.dialogs();
  for (size_t i = 0; i < dialogs.size(); ++i) {
    os << fmt::format("Dialog #{:02d}:\n{}\n", i, to_string(dialogs[i]));
  }

  const auto& str_table = rsrc.string_table();
  for (size_t i = 0; i < str_table.size(); ++i) {
    os << fmt::format("StringTable[{}]: {}", i, to_string(str_table[i]));
  }
  return os;
}

const char* to_string(ResourcesManager::TYPE type) {
  #define ENTRY(X) std::pair(ResourcesManager::TYPE::X, #X)
  STRING_MAP enums2str {
    ENTRY(CURSOR),
    ENTRY(BITMAP),
    ENTRY(ICON),
    ENTRY(MENU),
    ENTRY(DIALOG),
    ENTRY(STRING),
    ENTRY(FONTDIR),
    ENTRY(FONT),
    ENTRY(ACCELERATOR),
    ENTRY(RCDATA),
    ENTRY(MESSAGETABLE),
    ENTRY(GROUP_CURSOR),
    ENTRY(GROUP_ICON),
    ENTRY(VERSION),
    ENTRY(DLGINCLUDE),
    ENTRY(PLUGPLAY),
    ENTRY(VXD),
    ENTRY(ANICURSOR),
    ENTRY(ANIICON),
    ENTRY(HTML),
    ENTRY(MANIFEST),
  };
  #undef ENTRY

  if (auto it = enums2str.find(type); it != enums2str.end()) {
    return it->second;
  }

  return "UNKNOWN";
}


} // namespace PE
} // namespace LIEF
