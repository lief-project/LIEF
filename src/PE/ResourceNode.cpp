/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <cwctype>
#include <sstream>
#include <iomanip>

#include "logging.hpp"
#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {

ResourceNode::ResourceNode() = default;
ResourceNode::~ResourceNode() = default;

ResourceNode::ResourceNode(ResourceNode&& other) = default;
ResourceNode& ResourceNode::operator=(ResourceNode&& other) = default;

ResourceNode::ResourceNode(const ResourceNode& other) :
  Object{other},
  type_{other.type_},
  id_{other.id_},
  name_{other.name_},
  depth_{other.depth_}
{
  childs_.reserve(other.childs_.size());
  for (const std::unique_ptr<ResourceNode>& node : other.childs_) {
    childs_.emplace_back(node->clone());
  }
}

ResourceNode& ResourceNode::operator=(const ResourceNode& other) {
  if (this == &other) {
    return *this;
  }
  type_   = other.type_;
  id_     = other.id_;
  name_   = other.name_;
  depth_  = other.depth_;

  childs_.reserve(other.childs_.size());
  for (const std::unique_ptr<ResourceNode>& node : other.childs_) {
    childs_.emplace_back(node->clone());
  }
  return *this;
}

void ResourceNode::swap(ResourceNode& other) {
  std::swap(type_,   other.type_);
  std::swap(id_,     other.id_);
  std::swap(name_,   other.name_);
  std::swap(childs_, other.childs_);
  std::swap(depth_,  other.depth_);
}

uint32_t ResourceNode::id() const {
  return id_;
}


ResourceNode::it_childs ResourceNode::childs() {
  return childs_;
}


ResourceNode::it_const_childs ResourceNode::childs() const {
  return childs_;
}


const std::u16string& ResourceNode::name() const {
  return name_;
}


bool ResourceNode::is_directory() const {
  return type_ == TYPE::DIRECTORY;
}

bool ResourceNode::is_data() const {
  return type_ == TYPE::DATA;
}


bool ResourceNode::has_name() const {
  return static_cast<bool>(id() & 0x80000000);
}

uint32_t ResourceNode::depth() const {
  return depth_;
}


ResourceNode& ResourceNode::add_child(const ResourceDirectory& child) {

  auto new_node = std::make_unique<ResourceDirectory>(child);
  new_node->depth_ = depth_ + 1;

  if (is_directory()) {
    auto* dir = reinterpret_cast<ResourceDirectory*>(this);

    if (child.has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() + 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() + 1);
    }

    return **insert_child(std::move(new_node));
  }

  childs_.push_back(std::move(new_node));
  return *childs_.back();
}

ResourceNode& ResourceNode::add_child(const ResourceData& child) {
  auto new_node = std::make_unique<ResourceData>(child);
  new_node->depth_ = depth_ + 1;


  if (is_directory()) {
    auto* dir = reinterpret_cast<ResourceDirectory*>(this);

    if (child.has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() + 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() + 1);
    }

    return **insert_child(std::move(new_node));
  }
  childs_.push_back(std::move(new_node));
  return *childs_.back();
}

void ResourceNode::delete_child(uint32_t id) {

  const auto it_node = std::find_if(std::begin(childs_), std::end(childs_),
      [id] (const std::unique_ptr<ResourceNode>& node) {
        return node->id() == id;
      });

  if (it_node == std::end(childs_)) {
    LIEF_ERR("Unable to find the node with the id {:d}", id);
    return;
  }

  delete_child(**it_node);
}

void ResourceNode::delete_child(const ResourceNode& node) {
  const auto it_node = std::find_if(std::begin(childs_), std::end(childs_),
      [&node] (const std::unique_ptr<ResourceNode>& intree_node) {
        return *intree_node == node;
      });

  if (it_node == std::end(childs_)) {
    LIEF_ERR("Unable to find the node {}", node);
    return;
  }

  std::unique_ptr<ResourceNode>& inode = *it_node;

  if (is_directory()) {
    auto* dir = reinterpret_cast<ResourceDirectory*>(this);
    if (inode->has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() - 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() - 1);
    }
  }

  childs_.erase(it_node);
}

void ResourceNode::id(uint32_t id) {
  id_ = id;
}

void ResourceNode::name(const std::string& name) {
  this->name(u8tou16(name));
}

void ResourceNode::name(const std::u16string& name) {
  name_ = name;
}


// This logic follows the description from the Microsoft documentation at
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-table
//
// "(remember that all the Name entries precede all the ID entries for the table). All entries for the table
// "are sorted in ascending order: the Name entries by case-sensitive string and the ID entries by numeric value."
ResourceNode::childs_t::iterator ResourceNode::insert_child(std::unique_ptr<ResourceNode> child) {
  const auto it = std::upper_bound(childs_.begin(), childs_.end(), child,
      [] (const std::unique_ptr<ResourceNode>& lhs, const std::unique_ptr<ResourceNode>& rhs) {
        if (lhs->has_name() && rhs->has_name()) {
          // Case-sensitive string sort
          return std::lexicographical_compare(
              lhs->name().begin(), lhs->name().end(),
              rhs->name().begin(), rhs->name().end());
        } else if (!lhs->has_name() && !rhs->has_name()) {
          return lhs->id() < rhs->id();
        } else {
          // Named entries come first
          return lhs->has_name();
        }
      });

  return childs_.insert(it, std::move(child));
}

void ResourceNode::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceNode::operator==(const ResourceNode& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceNode::operator!=(const ResourceNode& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const ResourceNode& node) {
  if (node.is_directory()) {
    os << "[DIRECTORY]";
  } else {
    os << "[DATA]";
  }

  os << " - ID: 0x" << std::setw(2) << std::setfill('0') << std::hex << node.id();
  if (node.has_name()) {
    os << " (" << u16tou8(node.name()) << ")";
  }

  os << " - Depth: " << std::dec << node.depth();
  os << " - Childs : " << std::dec << node.childs().size();

  return os;

}


}
}
