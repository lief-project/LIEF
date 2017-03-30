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

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {

ResourceNode::ResourceNode(void) = default;

ResourceNode& ResourceNode::operator=(const ResourceNode& other) {
  if (this != &other) {
    this->type_ = other.type_;
    this->id_   = other.id_;
    this->name_ = other.name_;

    for (const ResourceNode* node : this->childs_) {
      if (const ResourceDirectory* directory = dynamic_cast<const ResourceDirectory*>(node)) {
        this->childs_.push_back(new ResourceDirectory{*directory});
      }

      if (const ResourceData* data = dynamic_cast<const ResourceData*>(node)) {
        this->childs_.push_back(new ResourceData{*data});
      }
    }
  }
  return *this;
}

ResourceNode::ResourceNode(const ResourceNode& other) {
  this->type_ = other.type_;
  this->id_   = other.id_;
  this->name_ = other.name_;

  for (const ResourceNode* node : this->childs_) {
    if (const ResourceDirectory* directory = dynamic_cast<const ResourceDirectory*>(node)) {
      this->childs_.push_back(new ResourceDirectory{*directory});
    }

    if (const ResourceData* data = dynamic_cast<const ResourceData*>(node)) {
      this->childs_.push_back(new ResourceData{*data});
    }
  }
}

ResourceNode::~ResourceNode(void) {
  for (ResourceNode* node : this->childs_) {
    delete node;
  }
}


RESOURCE_NODE_TYPES ResourceNode::type(void) const {
  return this->type_;
}


uint32_t ResourceNode::id(void) const {
  return this->id_;
}


std::vector<ResourceNode*>& ResourceNode::childs(void) {
  return this->childs_;
}


const std::vector<ResourceNode*>& ResourceNode::childs(void) const {
  return this->childs_;
}


const std::u16string& ResourceNode::name(void) const {
  return this->name_;
}


bool ResourceNode::has_name(void) const {
  return static_cast<bool>(this->id() & 0x80000000);
}


void ResourceNode::add_child(ResourceNode* child) {
  this->childs_.push_back(child);
}

void ResourceNode::accept(Visitor& visitor) const {

  visitor.visit(this->id());
  visitor.visit(static_cast<size_t>(this->type()));
  if (this->has_name()) {
    visitor.visit(this->name());
  }

  if (const ResourceDirectory* directory = dynamic_cast<const ResourceDirectory*>(this)) {
    visitor(*directory);
  }

  if (const ResourceData* data = dynamic_cast<const ResourceData*>(this)) {
    visitor(*data);
  }

  for (const ResourceNode* child : this->childs()) {
    visitor(*child);
  }

}

bool ResourceNode::operator==(const ResourceNode& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool ResourceNode::operator!=(const ResourceNode& rhs) const {
  return not (*this == rhs);
}


}
}
