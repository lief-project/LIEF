/* Copyright 2024 - 2025 R. Thomas
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
#pragma once
#include <cstdint>

#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/rust/PE/ResourceNode.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_ResourcesManager : private Mirror<LIEF::PE::ResourcesManager> {
  public:
  using lief_t = LIEF::PE::ResourcesManager;
  using Mirror::Mirror;

  auto find_node_type(uint32_t type) const {
    return details::try_unique<PE_ResourceNode>(
      get().get_node_type(LIEF::PE::ResourcesManager::TYPE(type)));
  }

  auto get_types() const {
    std::vector<uint32_t> values;
    auto types = get().get_types();
    std::transform(types.begin(), types.end(),
                   std::back_inserter(values),
      [] (LIEF::PE::ResourcesManager::TYPE ty) {
        return (uint32_t)ty;
      }
    );
    return values;
  }

  auto manifest() const { return get().manifest(); }
  void set_manifest(std::string str) { get().manifest(str); }
  auto print_tree() const { return get().print(); }

  auto print_tree_with_depth(uint32_t depth) const {
    return get().print(depth);
  }

};
