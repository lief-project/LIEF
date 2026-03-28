/* Copyright 2024 - 2026 R. Thomas
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
#include "LIEF/rust/PE/ResourceIcon.hpp"
#include "LIEF/rust/PE/ResourceVersion.hpp"
#include "LIEF/rust/PE/ResourceAccelerator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"

class PE_ResourcesManager_string_entry_t
  : private Mirror<LIEF::PE::ResourcesManager::string_entry_t> {
  public:
  using lief_t = LIEF::PE::ResourcesManager::string_entry_t;
  using Mirror::Mirror;

  auto string() const {
    return get().string_u8();
  }
  auto id() const {
    return get().id;
  }
};

class PE_ResourcesManager : private Mirror<LIEF::PE::ResourcesManager> {
  public:
  using lief_t = LIEF::PE::ResourcesManager;
  using Mirror::Mirror;

  class it_icons : public Iterator<PE_ResourceIcon,
                                   LIEF::PE::ResourcesManager::it_const_icons> {
    public:
    it_icons(const PE_ResourcesManager::lief_t& src) :
      Iterator(src.icons()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_version
    : public ContainerIterator<PE_ResourceVersion,
                               std::vector<LIEF::PE::ResourceVersion>> {
    public:
    it_version(const PE_ResourcesManager::lief_t& src) :
      ContainerIterator(src.version()) {}
    auto next() {
      return ContainerIterator::next();
    }
    auto size() const {
      return ContainerIterator::size();
    }
  };

  class it_accelerator
    : public Iterator<PE_ResourceAccelerator,
                      LIEF::PE::ResourcesManager::it_const_accelerators> {
    public:
    it_accelerator(const PE_ResourcesManager::lief_t& src) :
      Iterator(src.accelerator()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  class it_string_table_entry
    : public ContainerIterator<PE_ResourcesManager_string_entry_t,
                               LIEF::PE::ResourcesManager::strings_table_t> {
    public:
    using container_t = LIEF::PE::ResourcesManager::strings_table_t;
    it_string_table_entry(const PE_ResourcesManager::lief_t& src) :
      ContainerIterator(src.string_table()) {}
    auto next() {
      return ContainerIterator::next();
    }
    auto size() const {
      return ContainerIterator::size();
    }
  };

  auto find_node_type(uint32_t type) const {
    return details::try_unique<PE_ResourceNode>(
        get().get_node_type(LIEF::PE::ResourcesManager::TYPE(type))
    );
  }

  auto get_types() const {
    std::vector<uint32_t> values;
    auto types = get().get_types();
    std::transform(types.begin(), types.end(), std::back_inserter(values),
                   [](LIEF::PE::ResourcesManager::TYPE ty) {
                     return (uint32_t)ty;
                   });
    return values;
  }

  bool has_type(uint32_t type) const {
    return get().has_type(LIEF::PE::ResourcesManager::TYPE(type));
  }

  auto manifest() const {
    return get().manifest();
  }
  void set_manifest(std::string str) {
    get().manifest(str);
  }
  auto print_tree() const {
    return get().print();
  }

  auto print_tree_with_depth(uint32_t depth) const {
    return get().print(depth);
  }
  auto html() const {
    return get().html();
  }
  auto icons() const {
    return std::make_unique<it_icons>(get());
  }
  auto version() const {
    return std::make_unique<it_version>(get());
  }
  auto accelerator() const {
    return std::make_unique<it_accelerator>(get());
  }
  auto string_table() const {
    return std::make_unique<it_string_table_entry>(get());
  }
};
