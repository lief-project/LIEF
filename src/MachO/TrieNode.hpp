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
#ifndef LIEF_MACHO_TRIE_NODE_H_
#define LIEF_MACHO_TRIE_NODE_H_
#include <string>
#include <vector>
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/iostream.hpp"


namespace LIEF {
namespace MachO {
class TrieNode;

class LIEF_LOCAL TrieEdge {
  public:
  static std::unique_ptr<TrieEdge> create(const std::string& str, TrieNode& node);

  TrieEdge() = delete;
  TrieEdge(std::string str, TrieNode& node);

  ~TrieEdge();

  public:
  std::string substr;
  TrieNode* child = nullptr;
};


class LIEF_LOCAL TrieNode {

  public:
  using trie_edge_list_t = std::vector<std::unique_ptr<TrieEdge>>;
  using node_list_t = std::vector<std::unique_ptr<TrieNode>>;

  static std::unique_ptr<TrieNode> create(const std::string& str);

  TrieNode() = delete;

  TrieNode(std::string str);
  ~TrieNode();

  TrieNode& add_symbol(const ExportInfo& info, node_list_t& nodes);
  TrieNode& add_ordered_nodes(const ExportInfo& info, std::vector<TrieNode*>& nodes);
  bool update_offset(uint32_t& offset);

  TrieNode& write(vector_iostream& buffer);


  private:
  std::string cummulative_string_;
  trie_edge_list_t children_;
  uint64_t address_ = 0;
  uint64_t flags_ = 0;
  uint64_t other_ = 0;
  std::string imported_name_;
  uint32_t trie_offset_ = 0;
  bool has_export_info_ = false;
  bool ordered_ = false;

};

}
}

#endif
