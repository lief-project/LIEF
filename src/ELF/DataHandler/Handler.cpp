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

#include "LIEF/logging++.hpp"

#include "LIEF/ELF/DataHandler/Handler.hpp"
#include "LIEF/exception.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {

Handler::Handler(void) = default;
Handler& Handler::operator=(const Handler&) = default;
Handler::Handler(const Handler&) = default;

Handler::Handler(const std::vector<uint8_t>& content) :
  data_{content}
{}


Handler::Handler(std::vector<uint8_t>&& content) :
  data_{std::move(content)}
{}

const std::vector<uint8_t>& Handler::content(void) const {
  return this->data_;
}

std::vector<uint8_t>& Handler::content(void) {
  return const_cast<std::vector<uint8_t>&>(static_cast<const Handler*>(this)->content());
}

bool Handler::has(uint64_t offset, uint64_t size, Node::Type type) {
  Node tmp{offset, size, type};
  auto&& it_node = std::find_if(
      std::begin(this->nodes_),
      std::end(this->nodes_),
      [&tmp] (const Node* node)
      {
        return tmp == *node;
      });
  return it_node != std::end(this->nodes_);
}

Node& Handler::get(uint64_t offset, uint64_t size, Node::Type type) {
  Node tmp{offset, size, type};

  auto&& it_node = std::find_if(
        std::begin(this->nodes_),
        std::end(this->nodes_),
        [&tmp] (const Node* node)
        {
          return tmp == *node;
        });

  if (it_node != std::end(this->nodes_)) {
    return **it_node;
  } else {
    throw not_found("Unable to find node");
  }
}


void Handler::remove(uint64_t offset, uint64_t size, Node::Type type) {

  Node tmp{offset, size, type};

  auto&& it_node = std::find_if(
        std::begin(this->nodes_),
        std::end(this->nodes_),
        [&tmp] (const Node* node)
        {
          return tmp == *node;
        });

  if (it_node != std::end(this->nodes_)) {
    delete *it_node;
    this->nodes_.erase(it_node);
  } else {
    throw not_found("Unable to find node");
  }
}


Node& Handler::create(uint64_t offset, uint64_t size, Node::Type type) {
  this->nodes_.emplace_back(new Node{offset, size, type});
  return *this->nodes_.back();
}


Node& Handler::add(const Node& node) {
  this->nodes_.push_back(new Node{node});
  return *this->nodes_.back();
}

void Handler::make_hole(uint64_t offset, uint64_t size) {
  this->reserve(offset, size);
  this->data_.insert(std::begin(this->data_) + offset, size, 0);
}


void Handler::reserve(uint64_t offset, uint64_t size) {
  if ((offset + size) > Handler::MAX_SIZE) {
    throw std::bad_alloc();
  }
  if (this->data_.size() < (offset + size)) {
    this->data_.resize((offset + size), 0);
  }
}

Handler::~Handler(void) {
  for (Node* n : this->nodes_) {
    delete n;
  }
}

} // namespace DataHandler
} // namespace ELF
} // namespace LIEF
