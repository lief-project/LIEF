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
#ifndef LIEF_PE_RESOURCES_MANAGER_H_
#define LIEF_PE_RESOURCES_MANAGER_H_
#include <iostream>
#include <sstream>
#include <set>

#include "LIEF/errors.hpp"
#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/PE/resources/ResourceVersion.hpp"
#include "LIEF/PE/resources/ResourceIcon.hpp"
#include "LIEF/PE/resources/ResourceDialog.hpp"
#include "LIEF/PE/resources/ResourceStringTable.hpp"
#include "LIEF/PE/resources/ResourceAccelerator.hpp"

namespace LIEF {
class VectorStream;

namespace PE {

//! The Resource Manager provides an enhanced API to manipulate the resource tree.
class LIEF_API ResourcesManager : public Object {
  public:
  static RESOURCE_SUBLANGS sub_lang(RESOURCE_LANGS lang, size_t index);

  static RESOURCE_LANGS lang_from_id(size_t id);
  static RESOURCE_SUBLANGS sublang_from_id(size_t id);

  public:
  using dialogs_t = std::vector<ResourceDialog>;
  using it_const_dialogs = const_ref_iterator<dialogs_t>;

  using icons_t = std::vector<ResourceIcon>;
  using it_const_icons = const_ref_iterator<icons_t>;

  using strings_table_t = std::vector<ResourceStringTable>;
  using it_const_strings_table = const_ref_iterator<strings_table_t>;

  using accelerators_t = std::vector<ResourceAccelerator>;
  using it_const_accelerators = const_ref_iterator<accelerators_t>;

  ResourcesManager() = delete;
  ResourcesManager(ResourceNode& rsrc);

  ResourcesManager(const ResourcesManager&);
  ResourcesManager& operator=(const ResourcesManager&);

  ResourcesManager(ResourcesManager&&);
  ResourcesManager& operator=(ResourcesManager&&);

  virtual ~ResourcesManager();

  //! Return the ResourceNode associated with the given LIEF::PE::RESOURCE_TYPES
  //! or a nullptr if not found;
  ResourceNode*       get_node_type(RESOURCE_TYPES type);
  const ResourceNode* get_node_type(RESOURCE_TYPES type) const;

  //! List of LIEF::PE::RESOURCE_TYPES present in the resources
  std::set<RESOURCE_TYPES> get_types_available() const;

  //! List of LIEF::PE::RESOURCE_LANGS present in the resources
  std::set<RESOURCE_LANGS> get_langs_available() const;

  //! List of LIEF::PE::RESOURCE_SUBLANGS present in the resources
  std::set<RESOURCE_SUBLANGS> get_sublangs_available() const;

  //! ``true`` if the resource has the given LIEF::PE::RESOURCE_TYPES
  bool has_type(RESOURCE_TYPES type) const;

    //! ``true`` if resources contain the Manifest element
  bool has_manifest() const;

  //! Return the manifest as a std::string or an empty string if not found
  //! or corrupted
  std::string manifest() const;

  //! Update the manifest with the given string
  void manifest(const std::string& manifest);

  //! ``true`` if resources contain a LIEF::PE::ResourceVersion
  bool has_version() const;

  //! Return the ResourceVersion if any
  result<ResourceVersion> version() const;

  //! ``true`` if resources contain a LIEF::PE::ResourceIcon
  bool has_icons() const;

  //! Return the list of the icons present in the resources
  it_const_icons icons() const;

  //! Add an icon to the resources
  void add_icon(const ResourceIcon& icon);

  //void remove_icon(const ResourceIcon& icon)

  void change_icon(const ResourceIcon& original, const ResourceIcon& newone);

  //! ``true`` if resources contain @link LIEF::PE::ResourceDialog dialogs @endlink
  bool has_dialogs() const;

  //! Return the list of the dialogs present in the resource
  it_const_dialogs dialogs() const;

  //! ``true`` if the resources contain a @link LIEF::PE::ResourceStringTable @endlink
  bool has_string_table() const;

  //! Return the list of the string table in the resource
  it_const_strings_table string_table() const;

  // HTML
  // ====

  //! ``true`` if the resources contain html
  bool has_html() const;

  //! Return the list of the html resources
  std::vector<std::string> html() const;

  // Accelerator
  // =====

  //! ``true`` if the resources contain @link LIEF::PE::ResourceAccelerator @endlink
  bool has_accelerator() const;

  //! Return the list of the accelerator in the resource
  it_const_accelerators accelerator() const;

  //!Print the resource tree to the given depth
  std::string print(uint32_t depth = 0) const;

  void accept(Visitor& visitor) const override;

  bool operator==(const ResourcesManager& rhs) const;
  bool operator!=(const ResourcesManager& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourcesManager& m);

  private:
  void print_tree(const ResourceNode& node, std::ostringstream& stream,
                  uint32_t current_depth, uint32_t max_depth) const;
  ResourceNode* resources_ = nullptr;
};

} // namespace PE
} // namespace LIEF

#endif
