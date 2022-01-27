/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include <utility>

#include "logging.hpp"

#include "LIEF/BinaryStream/MemoryStream.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/DataHandler/Handler.hpp"
#include "LIEF/exception.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {

Handler::Handler() = default;
Handler& Handler::operator=(const Handler&) = default;
Handler::Handler(const Handler&) = default;

Handler::Handler(std::vector<uint8_t> content) :
  data_{std::move(content)}
{}


Handler::Handler(std::vector<uint8_t>&& content) :
  data_{std::move(content)}
{}

Handler::Handler(BinaryStream& stream) {

  switch (stream.type()) {
    case BinaryStream::STREAM_TYPE::FILE:
      {
        auto& vs = reinterpret_cast<VectorStream&>(stream);
        data_ = vs.content();
        break;
      }

    case BinaryStream::STREAM_TYPE::MEMORY:
      {
        throw std::runtime_error("Not impletemented yet");
        break;
      }

    case BinaryStream::STREAM_TYPE::UNKNOWN:
    default:
      {
        LIEF_ERR("Unknown stream type!");
      }
  }
}

const std::vector<uint8_t>& Handler::content() const {
  return data_;
}

std::vector<uint8_t>& Handler::content() {
  return const_cast<std::vector<uint8_t>&>(static_cast<const Handler*>(this)->content());
}

bool Handler::has(uint64_t offset, uint64_t size, Node::Type type) {
  Node tmp{offset, size, type};
  const auto it_node = std::find_if(std::begin(nodes_), std::end(nodes_),
                                    [&tmp] (const Node* node) { return tmp == *node; });
  return it_node != std::end(nodes_);
}

Node& Handler::get(uint64_t offset, uint64_t size, Node::Type type) {
  Node tmp{offset, size, type};

  const auto it_node = std::find_if(std::begin(nodes_), std::end(nodes_),
                                    [&tmp] (const Node* node) { return tmp == *node; });

  if (it_node != std::end(nodes_)) {
    return **it_node;
  } else {
    throw not_found("Unable to find node");
  }
}


void Handler::remove(uint64_t offset, uint64_t size, Node::Type type) {

  Node tmp{offset, size, type};

  const auto it_node = std::find_if(std::begin(nodes_), std::end(nodes_),
                                    [&tmp] (const Node* node) { return tmp == *node; });

  if (it_node != std::end(nodes_)) {
    delete *it_node;
    nodes_.erase(it_node);
  } else {
    throw not_found("Unable to find node");
  }
}


Node& Handler::create(uint64_t offset, uint64_t size, Node::Type type) {
  nodes_.emplace_back(new Node{offset, size, type});
  return *nodes_.back();
}


Node& Handler::add(const Node& node) {
  nodes_.push_back(new Node{node});
  return *nodes_.back();
}

void Handler::make_hole(uint64_t offset, uint64_t size) {
  reserve(offset, size);
  data_.insert(std::begin(data_) + offset, size, 0);
}


void Handler::reserve(uint64_t offset, uint64_t size) {
  if ((offset + size) > Handler::MAX_SIZE) {
    throw std::bad_alloc();
  }
  if (data_.size() < (offset + size)) {
    data_.resize((offset + size), 0);
  }
}

Handler::~Handler() {
  for (Node* n : nodes_) {
    delete n;
  }
}

} // namespace DataHandler
} // namespace ELF
} // namespace LIEF
