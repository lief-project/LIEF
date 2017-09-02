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
#include "LIEF/ELF/DataHandler/Node.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {

Node& Node::operator=(const Node&) = default;
Node::Node(const Node&) = default;

Node::Node(void) :
  size_{0},
  offset_{0},
  type_{UNKNOWN}
{}


Node::Node(uint64_t offset, uint64_t size, Type type) :
  size_{size},
  offset_{offset},
  type_{type}
{}

uint64_t Node::size(void) const {
  return this->size_;
}


uint64_t Node::offset(void) const {
  return this->offset_;
}


Node::Type Node::type(void) const {
  return this->type_;
}

void Node::size(uint64_t size) {
  this->size_ = size;
}


void Node::type(Node::Type type) {
  this->type_ = type;
}


void Node::offset(uint64_t offset) {
  this->offset_ = offset;
}


bool Node::operator==(const Node& rhs) const {
  return this->type() == rhs.type() and
         this->size() == rhs.size() and
         this->offset() == rhs.offset();
}

bool Node::operator!=(const Node& rhs) const {
  return not (*this == rhs);
}

bool Node::operator<(const Node& rhs) const {
  return ((this->type() == rhs.type() and
         this->offset() <= rhs.offset() and
         (this->offset() + this->size()) < (rhs.offset() + rhs.size())) or
         (this->type() == rhs.type() and
         this->offset() < rhs.offset() and
         (this->offset() + this->size()) <= (rhs.offset() + rhs.size())));

}

bool Node::operator<=(const Node& rhs) const {
  return (this->type() == rhs.type() and not (*this > rhs));
}

bool Node::operator>(const Node& rhs) const {
  return this->type() == rhs.type() and
        (this->offset() > rhs.offset() or (this->offset() + this->size()) > (rhs.offset() + rhs.size()));
}

bool Node::operator>=(const Node& rhs) const {
  return (this->type() == rhs.type() and not (*this < rhs));
}

}
}
}
