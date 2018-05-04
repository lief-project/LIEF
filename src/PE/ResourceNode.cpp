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
#include <sstream>
#include <iomanip>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {

ResourceNode::ResourceNode(void) :
  id_{0},
  name_{},
  childs_{},
  depth_{0}
{}


//ResourceNode& ResourceNode::operator=(ResourceNode other) {
//  this->swap(other);
//  return *this;
//}

ResourceNode::ResourceNode(const ResourceNode& other) :
  Object{other},
  id_{other.id_},
  name_{other.name_},
  depth_{other.depth_}
{
  this->childs_.reserve(other.childs_.size());
  for (const ResourceNode* node : other.childs_) {
    this->childs_.push_back(node->clone());
  }
}


void ResourceNode::swap(ResourceNode& other) {
  std::swap(this->id_,     other.id_);
  std::swap(this->name_,   other.name_);
  std::swap(this->childs_, other.childs_);
  std::swap(this->depth_,  other.depth_);
}

ResourceNode::~ResourceNode(void) {
  for (ResourceNode* node : this->childs_) {
    delete node;
  }
}


uint32_t ResourceNode::id(void) const {
  return this->id_;
}


it_childs ResourceNode::childs(void) {
  return {this->childs_};
}


it_const_childs ResourceNode::childs(void) const {
  return {this->childs_};
}


const std::u16string& ResourceNode::name(void) const {
  return this->name_;
}


bool ResourceNode::is_directory(void) const {
  return typeid(*this) == typeid(ResourceDirectory);
}

bool ResourceNode::is_data(void) const {
  return not this->is_directory();
}


bool ResourceNode::has_name(void) const {
  return static_cast<bool>(this->id() & 0x80000000);
}

uint32_t ResourceNode::depth(void) const {
  return this->depth_;
}


ResourceNode& ResourceNode::add_child(const ResourceDirectory& child) {

  ResourceDirectory* new_node = new ResourceDirectory{child};
  new_node->depth_ = this->depth_ + 1;

  this->childs_.push_back(new_node);

  if (ResourceDirectory* dir = dynamic_cast<ResourceDirectory*>(this)) {
    if (this->has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() + 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() + 1);
    }
  }

  return *this->childs_.back();
}

ResourceNode& ResourceNode::add_child(const ResourceData& child) {
  ResourceData* new_node = new ResourceData{child};
  new_node->depth_ = this->depth_ + 1;

  this->childs_.push_back(new_node);

  if (ResourceDirectory* dir = dynamic_cast<ResourceDirectory*>(this)) {
    if (this->has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() + 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() + 1);
    }
  }
  return *this->childs_.back();
}

void ResourceNode::delete_child(uint32_t id) {

  auto&& it_node = std::find_if(
      std::begin(this->childs_),
      std::end(this->childs_),
      [id] (const ResourceNode* node) {
        return node->id() == id;
      });

  if (it_node == std::end(this->childs_)) {
    throw not_found("Unable to find the node with id " + std::to_string(id) + "!");
  }
  this->delete_child(**it_node);

}

void ResourceNode::delete_child(const ResourceNode& node) {
  auto&& it_node = std::find_if(
      std::begin(this->childs_),
      std::end(this->childs_),
      [&node] (const ResourceNode* intree_node) {
        return *intree_node == node;
      });

  if (it_node == std::end(this->childs_)) {
    std::stringstream ss;
    ss << "Unable to find the node: " << node;
    throw not_found(ss.str());
  }

  if (this->is_directory()) {
    ResourceDirectory* dir = dynamic_cast<ResourceDirectory*>(this);
    if (this->has_name()) {
      dir->numberof_name_entries(dir->numberof_name_entries() - 1);
    } else {
      dir->numberof_id_entries(dir->numberof_id_entries() - 1);
    }
  }

  delete *it_node;
  this->childs_.erase(it_node);

}

void ResourceNode::id(uint32_t id) {
  this->id_ = id;
}

void ResourceNode::name(const std::string& name) {
  this->name(u8tou16(name));
}

void ResourceNode::name(const std::u16string& name) {
  this->name_ = name;
}


void ResourceNode::sort_by_id(void) {
  std::sort(
      std::begin(this->childs_),
      std::end(this->childs_),
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
  return not (*this == rhs);
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
