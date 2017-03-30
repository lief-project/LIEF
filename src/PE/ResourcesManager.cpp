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
#include <algorithm>
#include <iomanip>

#include "rang.hpp"

#include "LIEF/exception.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/ResourcesManager.hpp"

namespace LIEF {
namespace PE {

ResourcesManager::ResourcesManager(const ResourcesManager&) = default;
ResourcesManager& ResourcesManager::operator=(const ResourcesManager&) = default;
ResourcesManager::~ResourcesManager(void) = default;

ResourcesManager::ResourcesManager(ResourceNode *rsrc) :
  resources_{rsrc}
{}


ResourceDirectory* ResourcesManager::cursor(void) {
  std::vector<ResourceNode*> childs = this->resources_->childs();
  auto&& it_cursor = std::find_if(
      std::begin(childs),
      std::end(childs),
      [] (const ResourceNode* node) {
        return (
            node->type() == RESOURCE_NODE_TYPES::DIRECTORY and
            node->id() == RESOURCE_TYPES::CURSOR);
      });
  if (it_cursor == std::end(childs)) {
    throw not_found("Unable to find the resource directory associated with 'cursor'");
  }

  return static_cast<ResourceDirectory*>(*it_cursor);

}

std::string ResourcesManager::print(uint32_t depth) const {
  std::ostringstream oss;
  oss << rang::control::forceColor;
  uint32_t current_depth = 0;
  this->print_tree(*this->resources_, oss, current_depth, depth);
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

  for (const ResourceNode* child_node : const_cast<ResourceNode&>(node).childs()) {
    output << std::string(2 * (current_depth + 1), ' ');
    output << "[";
    if (child_node->type() == RESOURCE_NODE_TYPES::DIRECTORY) {
      output << rang::fg::cyan;
      output << "Directory";
    } else {
      output << rang::fg::yellow;
      output << "Data";
    }

    output << rang::style::reset;
    output << "] ";

    if (child_node->has_name()) {

      output << rang::bg::blue;
      output << u16tou8(child_node->name());
      output << rang::style::reset;
    } else {
      output << "ID: " << std::setw(2) << std::setfill('0') << std::dec << child_node->id();
      output << std::setfill(' ');
    }
    output << std::endl;
    print_tree(*child_node, output, current_depth + 1, max_depth);
  }

}

std::ostream& operator<<(std::ostream& os, const ResourcesManager& m) {
  os << m.print(3);
  //os << m.print(static_cast<uint32_t>(-1));
  return os;
}

} // namespace PE
} // namespace LIEF
