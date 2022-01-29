/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include <sstream>
#include <iomanip>

#include "LIEF/PE/hash.hpp"

#include "LIEF/utils.hpp"

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {

ResourceNode::ResourceNode() = default;

ResourceNode::ResourceNode(const ResourceNode& other) :
  Object{other},
  type_{other.type_},
  id_{other.id_},
  name_{other.name_},
  depth_{other.depth_}
{
  childs_.reserve(other.childs_.size());
  for (const ResourceNode* node : other.childs_) {
    childs_.push_back(node->clone());
  }
}

void ResourceNode::swap(ResourceNode& other) {
  std::swap(type_,   other.type_);
  std::swap(id_,     other.id_);
  std::swap(name_,   other.name_);
  std::swap(childs_, other.childs_);
  std::swap(depth_,  other.depth_);
}

ResourceNode::~ResourceNode() {
  for (ResourceNode* node : childs_) {
    delete node;
  }
}


uint32_t ResourceNode::id() const {
  return id_;
}


it_childs ResourceNode::childs() {
  return {childs_};
}


it_const_childs ResourceNode::childs() const {
  return {childs_};
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

  auto* new_node = new ResourceDirectory{child};
  new_node->depth_ = depth_ + 1;

  childs_.push_back(new_node);

  if (auto* dir = dynamic_cast<ResourceDirectory*>(this)) {
    if (child.has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() + 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() + 1);
    }
  }

  return *childs_.back();
}

ResourceNode& ResourceNode::add_child(const ResourceData& child) {
  auto* new_node = new ResourceData{child};
  new_node->depth_ = depth_ + 1;

  childs_.push_back(new_node);

  if (auto* dir = dynamic_cast<ResourceDirectory*>(this)) {
    if (child.has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() + 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() + 1);
    }
  }
  return *childs_.back();
}

void ResourceNode::delete_child(uint32_t id) {

  const auto it_node = std::find_if(std::begin(childs_), std::end(childs_),
      [id] (const ResourceNode* node) {
        return node->id() == id;
      });

  if (it_node == std::end(childs_)) {
    throw not_found("Unable to find the node with id " + std::to_string(id) + "!");
  }
  delete_child(**it_node);

}

void ResourceNode::delete_child(const ResourceNode& node) {
  const auto it_node = std::find_if(std::begin(childs_), std::end(childs_),
      [&node] (const ResourceNode* intree_node) {
        return *intree_node == node;
      });

  if (it_node == std::end(childs_)) {
    std::stringstream ss;
    ss << "Unable to find the node: " << node;
    throw not_found(ss.str());
  }

  if (is_directory()) {
    auto* dir = dynamic_cast<ResourceDirectory*>(this);
    if ((*it_node)->has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() - 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() - 1);
    }
  }

  delete *it_node;
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


void ResourceNode::sort_by_id() {
  std::sort(
      std::begin(childs_),
      std::end(childs_),
      [] (const ResourceNode* lhs, const ResourceNode* rhs) {
        return lhs->id() < rhs->id();
      });
}

void ResourceNode::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool ResourceNode::operator==(const ResourceNode& rhs) const {
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
