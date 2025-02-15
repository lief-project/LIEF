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

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"

class PE_ResourceNode : public Mirror<LIEF::PE::ResourceNode> {
  public:
  using lief_t = LIEF::PE::ResourceNode;
  using Mirror::Mirror;

  class it_childs :
      public Iterator<PE_ResourceNode, LIEF::PE::ResourceNode::it_const_childs>
  {
    public:
    it_childs(const PE_ResourceNode::lief_t& src)
      : Iterator(std::move(src.childs())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  static auto from_slice(const uint8_t* buffer, size_t size, uint64_t rva) {
    return details::try_unique<PE_ResourceNode>(LIEF::PE::ResourceNode::parse(buffer, size, rva));
  }

  auto has_name() const { return get().has_name(); }
  auto name() const { return get().utf8_name(); }

  auto id() const { return get().id(); }
  auto depth() const { return get().depth(); }
  auto is_directory() const { return get().is_directory(); }
  auto is_data() const { return get().is_data(); }
  auto childs() const {
    return std::make_unique<it_childs>(get());
  }

  auto add_child(const PE_ResourceNode& node) {
    return std::make_unique<PE_ResourceNode>(get().add_child(node.get()));
  }

  void delete_child(uint32_t id) {
    get().delete_child(id);
  }

  auto print() const { return get().to_string(); }
};
