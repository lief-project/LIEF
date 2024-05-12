/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_PE_RESOURCE_NODE_H
#define LIEF_PE_RESOURCE_NODE_H
#include <string>
#include <vector>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"

namespace LIEF {
namespace PE {

class ResourceDirectory;
class ResourceData;

class Parser;
class Builder;

//! Class which represents a Node in the resource tree.
class LIEF_API ResourceNode : public Object {

  friend class Parser;
  friend class Builder;

  public:
  using childs_t        = std::vector<std::unique_ptr<ResourceNode>>;
  using it_childs       = ref_iterator<childs_t&, ResourceNode*>;
  using it_const_childs = const_ref_iterator<const childs_t&, ResourceNode*>;

  /// Enum that identifies the type of a node in the resource tree
  enum class TYPE {
    UNKNOWN = 0,
    DATA,
    DIRECTORY,
  };

  ResourceNode(const ResourceNode& other);
  ResourceNode& operator=(const ResourceNode& other);

  ResourceNode(ResourceNode&& other);
  ResourceNode& operator=(ResourceNode&& other);

  void swap(ResourceNode& other);

  ~ResourceNode() override;

  virtual std::unique_ptr<ResourceNode> clone() const = 0;

  //! Integer that identifies the Type, Name, or Language ID of the entry
  //! depending on its depth in the tree
  uint32_t id() const {
    return id_;
  }

  //! Name of the entry
  const std::u16string& name() const {
    return name_;
  }

  //! Iterator on node's children
  it_childs childs() {
    return childs_;
  }
  it_const_childs childs() const {
    return childs_;
  }

  //! ``True`` if the entry uses a name as ID
  bool has_name() const {
    return static_cast<bool>(id() & 0x80000000);
  }

  //! Current depth of the Node in the resource tree
  uint32_t depth() const {
    return depth_;
  }

  //! ``True`` if the current entry is a ResourceDirectory.
  //!
  //! It can be safely casted with:
  //!
  //! ```cpp
  //! const auto& dir_node = static_cast<const ResourceDirectory&>(node);
  //! ```
  bool is_directory() const {
    return type_ == TYPE::DIRECTORY;
  }

  //! ``True`` if the current entry is a ResourceData.
  //!
  //! It can be safely casted with:
  //!
  //! ```cpp
  //! const auto& data_node = static_cast<const ResourceData&>(node);
  //! ```
  bool is_data() const {
    return type_ == TYPE::DATA;
  }

  void id(uint32_t id) {
    id_ = id;
  }
  void name(const std::string& name);

  void name(std::u16string name) {
    name_ = std::move(name);
  }

  //! Add a ResourceDirectory to the current node
  ResourceNode& add_child(const ResourceDirectory& child);

  //! Add a ResourceData to the current node
  ResourceNode& add_child(const ResourceData& child);

  //! Delete the node with the given ``id``
  void delete_child(uint32_t id);

  //! Delete the given node from the node's children
  void delete_child(const ResourceNode& node);

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceNode& node);

  protected:
  ResourceNode();
  ResourceNode(TYPE type);
  childs_t::iterator insert_child(std::unique_ptr<ResourceNode> child);
  TYPE           type_ = TYPE::UNKNOWN;
  uint32_t       id_ = 0;
  std::u16string name_;
  childs_t       childs_;
  uint32_t       depth_ = 0;
};
}
}
#endif /* RESOURCENODE_H */
