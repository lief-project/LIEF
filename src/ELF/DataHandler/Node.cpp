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
#include "ELF/DataHandler/Node.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {

Node& Node::operator=(const Node&) = default;
Node::Node(const Node&) = default;
Node::~Node() = default;

Node::Node() = default;

Node::Node(uint64_t offset, uint64_t size, Type type)
    : size_{size}, offset_{offset}, type_{type} {}

uint64_t Node::size() const { return size_; }

uint64_t Node::offset() const { return offset_; }

Node::Type Node::type() const { return type_; }

void Node::size(uint64_t size) { size_ = size; }

void Node::type(Node::Type type) { type_ = type; }

void Node::offset(uint64_t offset) { offset_ = offset; }

bool Node::operator==(const Node& rhs) const {
  if (this == &rhs) {
    return true;
  }
  return type() == rhs.type() && size() == rhs.size() &&
         offset() == rhs.offset();
}

bool Node::operator!=(const Node& rhs) const { return !(*this == rhs); }

bool Node::operator<(const Node& rhs) const {
  return ((type() == rhs.type() && offset() <= rhs.offset() &&
           (offset() + size()) < (rhs.offset() + rhs.size())) ||
          (type() == rhs.type() && offset() < rhs.offset() &&
           (offset() + size()) <= (rhs.offset() + rhs.size())));
}

bool Node::operator<=(const Node& rhs) const {
  return (type() == rhs.type() && !(*this > rhs));
}

bool Node::operator>(const Node& rhs) const {
  return type() == rhs.type() &&
         (offset() > rhs.offset() ||
          (offset() + size()) > (rhs.offset() + rhs.size()));
}

bool Node::operator>=(const Node& rhs) const {
  return (type() == rhs.type() && !(*this < rhs));
}

}  // namespace DataHandler
}  // namespace ELF
}  // namespace LIEF
