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
#include <iostream>
#include <stdexcept>
#include <algorithm>

#include "easylogging++.h"

#include "LIEF/ELF/DataHandler/Handler.hpp"
#include "LIEF/exception.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {

Handler::Handler(void) = default;
Handler::~Handler(void) = default;
Handler& Handler::operator=(const Handler&) = default;
Handler::Handler(const Handler&) = default;

Handler::Handler(const std::vector<uint8_t>& content) :
  data_{content}
{}

//! \brief return the raw content
const std::vector<uint8_t>& Handler::content(void) const {
  return this->data_;
}

/*! \brief return the content from offset and size
 *
 * First we have to find the node which hold the content
 * if the node does not exist we throw an exception because we wants to read
 * something which is not hold by `section` or `segment`
 * if the node exist we return the raw content
 */
std::vector<uint8_t> Handler::content(uint64_t offset, uint64_t size, Node::Type type) {
  if (offset > this->data_.size() or (offset + size) > this->data_.size()) {
    VLOG(VDEBUG) << "Offset: 0x" << std::hex << offset;
    VLOG(VDEBUG) << "Size: 0x" << std::hex << size;
    VLOG(VDEBUG) << "Data size" << std::hex << this->data_.size();
    throw std::runtime_error("Invalid data access");
  }
  Node& node = this->find(offset, size, false, type);
  uint64_t relativeOffset = offset - node.offset();
    return {
      this->data_.data() + node.offset() + relativeOffset,
      this->data_.data() + node.offset() + relativeOffset + size
    };

}

/*! \brief Insert content in the raw data
 *
 * First we check if the container is large enough to insert the new data
 * Then we check if a node exist for this data. If yes, we replace the raw data with the new data
 * if not we create a node to hold this data and then we insert data
 */
void Handler::content(uint64_t offset, const std::vector<uint8_t>& content, Node::Type type) {

  if (this->data_.size() < (offset + content.size())) {
    this->data_.resize(offset + content.size());
  }

  if (content.size() == 0) {
    return;
  }

  try {
    Node& node = this->find(offset, content.size(), true, type);
    std::copy(std::begin(content), std::end(content), this->data_.data() + node.offset());
  } catch (const not_found&) {
    Node nodeCreated = {offset, content.size(), type};
    std::copy(std::begin(content), std::end(content), this->data_.data() + nodeCreated.offset());
    this->nodes_.push_back(std::move(nodeCreated));
  }

}

/*! \brief Find the node associated with the following parameters
 *  \return `nullptr` if the node doesn't exist else the node
 *
 *  To complete
 *
 */
Node& Handler::find(uint64_t offset, uint64_t size, bool insert, Node::Type type) {

  if (insert) {
    auto&& itNode = std::find_if(
        std::begin(this->nodes_),
        std::end(this->nodes_),
        [&offset, &size, &type] (const Node& node)
        {
          return node.type() == type and (node.offset() == offset) and ((offset + size) == (node.offset() + node.size()));
        });

    if (itNode != std::end(this->nodes_)) {
      return *itNode;
    } else {
      throw LIEF::not_found("Node not found (set)");
    }
  } else {
    auto&& itNode = std::find_if(
        std::begin(this->nodes_),
        std::end(this->nodes_),
        [&offset, &size, &type] (const Node& node)
        {
          return node.type() == type and (node.offset() <= offset) and ((offset + size) <= (node.offset() + node.size()));
        });

    if (itNode != std::end(this->nodes_)) {
      return *itNode;
    } else {
      this->nodes_.emplace_back(offset, size, type);
      return this->nodes_.back();
    }
  }
}

void Handler::move(Node& node, uint64_t newOffset) {
  if (newOffset < node.offset()) {
    throw LIEF::not_implemented("Handler::move shift << not implemented");
  }

  uint64_t originalOffset = node.offset();
  uint64_t shift          = newOffset - originalOffset;

  // Virtual shift. Use makeHole to physical shift
  for (Node& child : this->nodes_) {
    if (child.type() == node.type() and child.offset() > originalOffset) {
      child.offset(child.offset() + shift);
    }
  }

}

void Handler::add_node(const Node& node) {
  this->nodes_.push_back(node);
}

void Handler::make_hole(uint64_t offset, uint64_t size) {
  if (this->data_.size() < (offset + size)) {
    this->data_.resize((offset + size));
  }
  this->data_.insert(std::begin(this->data_) + offset, size, 0);
}

} // namespace DataHandler
} // namespace ELF
} // namespace LIEF
