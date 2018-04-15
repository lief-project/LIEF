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
#ifndef LIEF_PE_RESOURCES_MANAGER_H_
#define LIEF_PE_RESOURCES_MANAGER_H_
#include <iostream>
#include <sstream>
#include <set>

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/type_traits.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include "LIEF/PE/resources/ResourceVersion.hpp"
#include "LIEF/PE/resources/ResourceIcon.hpp"
#include "LIEF/PE/resources/ResourceDialog.hpp"

namespace LIEF {
namespace PE {

//! @brief The Resource Manager provides an enhanced API to
//! manipulate the resource tree.
class LIEF_API ResourcesManager : public Object {
  public:
  static RESOURCE_SUBLANGS sub_lang(RESOURCE_LANGS lang, size_t index);

  static RESOURCE_LANGS lang_from_id(size_t id);
  static RESOURCE_SUBLANGS sublang_from_id(size_t id);

  public:
  ResourcesManager(void) = delete;
  ResourcesManager(ResourceNode *rsrc);

  ResourcesManager(const ResourcesManager&);
  ResourcesManager& operator=(const ResourcesManager&);
  virtual ~ResourcesManager(void);

  // Enhancemed API to explore resource tree
  // =======================================

  //! @brief Return @link ResourceNode node @endlink with the given LIEF::PE::RESOURCE_TYPES
  ResourceNode&       get_node_type(RESOURCE_TYPES type);
  const ResourceNode& get_node_type(RESOURCE_TYPES type) const;

  //! @brief Return list of LIEF::PE::RESOURCE_TYPES present in the resources
  std::set<RESOURCE_TYPES> get_types_available(void) const;

  //! @brief Return list of LIEF::PE::RESOURCE_LANGS present in the resources
  std::set<RESOURCE_LANGS> get_langs_available(void) const;

  //! @brief Return list of LIEF::PE::RESOURCE_SUBLANGS present in the resources
  std::set<RESOURCE_SUBLANGS> get_sublangs_available(void) const;

  //! @brief ``true`` if the resource has the given LIEF::PE::RESOURCE_TYPES
  bool has_type(RESOURCE_TYPES type) const;

  // Manifest
  // ========

  //! @brief ``true`` if resources contain Manifest element
  bool has_manifest(void) const;

  //! @brief Return the manifest as a std::string
  std::string manifest(void) const;

  //! @brief Update the manifest with the given string
  void manifest(const std::string& manifest);


  // Version
  // =======

  //! @brief ``true`` if resources contain LIEF::PE::ResourceVersion
  bool has_version(void) const;

  //! @brief Return ResourceVersion if any
  ResourceVersion version(void) const;

  // Icons
  // =====

  //! @brief ``true`` if resources contain LIEF::PE::ResourceIcon
  bool has_icons(void) const;

  //! @brief Return the list of the icons present in the resource
  std::vector<ResourceIcon> icons(void) const;

  //! @brief Add an icon to the resources
  void add_icon(const ResourceIcon& icon);

  //void remove_icon(const ResourceIcon& icon)

  void change_icon(const ResourceIcon& original, const ResourceIcon& newone);

  // Dialogs
  // =======

  //! @brief ``true`` if resources contain @link LIEF::PE::ResourceDialog dialogs @endlink
  bool has_dialogs(void) const;

  //! @brief Return the list of the dialogs present in the resource
  std::vector<ResourceDialog> dialogs(void) const;

  // Print
  // =====

  //! @brief Print the resource tree to the given depth
  std::string print(uint32_t depth = 0) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourcesManager& rhs) const;
  bool operator!=(const ResourcesManager& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourcesManager& m);

  private:
  void print_tree(
      const ResourceNode& node,
      std::ostringstream& stream,
      uint32_t current_depth,
      uint32_t max_depth) const;

  //! @brief Build the ResourceStringFileInfo from the RT_VERSION node
  ResourceStringFileInfo get_string_file_info(const VectorStream& stream, uint16_t type, std::u16string key, size_t start, size_t struct_length) const;

  //! @brief Build the ResourceVarFileInfo from the RT_VERSION node
  ResourceVarFileInfo get_var_file_info(const VectorStream& stream, uint16_t type, std::u16string key, size_t start, size_t struct_length) const;


  ResourceNode *resources_;
};

} // namespace PE
} // namespace LIEF

#endif
