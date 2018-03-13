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
#ifndef LIEF_PE_RESOURCE_NODE_H_
#define LIEF_PE_RESOURCE_NODE_H_

#include <string>
#include <vector>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/type_traits.hpp"
#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

class ResourceDirectory;
class ResourceData;

class Parser;
class Builder;

class LIEF_API ResourceNode : public Object {

  friend class Parser;
  friend class Builder;

  public:
  ResourceNode(const ResourceNode& other);
  //ResourceNode& operator=(ResourceNode other);

  void swap(ResourceNode& other);

  virtual ~ResourceNode(void);

  virtual ResourceNode* clone(void) const = 0;

  //! @brief Integer that identifies the Type, Name, or
  //! Language ID entry.
  uint32_t id(void) const;

  //! @brief Name of the entry
  const std::u16string& name(void) const;

  //! @brief Iterator on node's childs
  it_childs       childs(void);
  it_const_childs childs(void) const;

  //! @brief ``True`` if the entry uses name as ID
  bool has_name(void) const;

  //! @brief Current depth of the entry in the resource tree
  uint32_t depth(void) const;

  //! @brief ``True`` if the current entry is a ResourceDirectory
  bool is_directory(void) const;

  //! @brief ``True`` if the current entry is a ResourceData
  bool is_data(void) const;

  void id(uint32_t id);
  void name(const std::string& name);
  void name(const std::u16string& name);

  //! @brief Add a ResourceDirectory to the current node
  ResourceNode& add_child(const ResourceDirectory& child);

  //! @brief Add a ResourceData to the current node
  ResourceNode& add_child(const ResourceData& child);

  //! @brief Delete the node with the given ``id``
  void delete_child(uint32_t id);

  //! @brief Delete the given node from childs
  void delete_child(const ResourceNode& node);

  //! @brief Sort resource childs by ID
  void sort_by_id(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceNode& rhs) const;
  bool operator!=(const ResourceNode& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceNode& node);

  protected:
  ResourceNode(void);

  uint32_t       id_;
  std::u16string name_;
  childs_t       childs_;
  uint32_t       depth_;
};
}
}
#endif /* RESOURCENODE_H_ */
