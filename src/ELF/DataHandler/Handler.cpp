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
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <utility>

#include "logging.hpp"

#include "LIEF/BinaryStream/MemoryStream.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "LIEF/BinaryStream/FileStream.hpp"

#include "ELF/DataHandler/Handler.hpp"
#include "LIEF/exception.hpp"

namespace LIEF {
namespace ELF {
namespace DataHandler {


//class DataHandlerStream : public SpanStream {
//  public:
//  DataHandlerStream(std::vector<uint8_t>& ref, size_t non_aligned_size) :
//    SpanStream({ref.data(), non_aligned_size})
//  {
//    stype_ = STREAM_TYPE::ELF_DATA_HANDLER;
//  }
//  ~DataHandlerStream() override = default;
//};
class DataHandlerStream : public BinaryStream {
  public:
  DataHandlerStream(std::vector<uint8_t>& ref) :
    data_{ref}
  {
    stype_ = STREAM_TYPE::ELF_DATA_HANDLER;
  }
  ~DataHandlerStream() override = default;

  inline uint64_t size() const override {
    return data_.size();
  }

  inline result<const void*> read_at(uint64_t offset, uint64_t size) const override {
    if (offset > data_.size() || (offset + size) > data_.size()) {
      return make_error_code(lief_errors::read_error);
    }
    return data_.data() + offset;
  }

  private:
  std::vector<uint8_t>& data_;
};

Handler::~Handler() = default;
Handler::Handler() = default;

Handler& Handler::operator=(Handler&&) = default;
Handler::Handler(Handler&&) = default;

Handler::Handler(std::vector<uint8_t> content) :
  data_{std::move(content)}
{}


Handler::Handler(std::vector<uint8_t>&& content) :
  data_{std::move(content)}
{}


result<std::unique_ptr<Handler>> Handler::from_stream(std::unique_ptr<BinaryStream>& stream) {
  auto hdl = std::unique_ptr<Handler>(new Handler{});
  if (VectorStream::classof(*stream)) {
    auto& vs = static_cast<VectorStream&>(*stream);

    hdl->data_ = std::move(vs.move_content());
    const uint64_t pos = vs.pos();
    stream = std::make_unique<DataHandlerStream>(hdl->data_);
    stream->setpos(pos);
    return hdl;
  }

  if (SpanStream::classof(*stream)) {
    auto& vs = static_cast<SpanStream&>(*stream);
    hdl->data_ = vs.content();
    return hdl;
  }

  if (FileStream::classof(*stream)) {
    auto& vs = static_cast<FileStream&>(*stream);
    hdl->data_ = vs.content();
    const uint64_t pos = vs.pos();
    stream = std::make_unique<DataHandlerStream>(hdl->data_);
    stream->setpos(pos);
    return hdl;
  }

  if (MemoryStream::classof(*stream)) {
    return make_error_code(lief_errors::not_implemented);
  }

  LIEF_ERR("Unknown stream for Handler");
  return make_error_code(lief_errors::not_supported);
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
                                    [&tmp] (const std::unique_ptr<Node>& node) {
                                      return tmp == *node;
                                    });
  return it_node != std::end(nodes_);
}

result<Node&> Handler::get(uint64_t offset, uint64_t size, Node::Type type) {
  Node tmp{offset, size, type};

  const auto it_node = std::find_if(std::begin(nodes_), std::end(nodes_),
                                    [&tmp] (const std::unique_ptr<Node>& node) {
                                      return tmp == *node;
                                    });

  if (it_node == std::end(nodes_)) {
    return make_error_code(lief_errors::not_found);
  }
  return **it_node;
}


void Handler::remove(uint64_t offset, uint64_t size, Node::Type type) {

  Node tmp{offset, size, type};

  const auto it_node = std::find_if(std::begin(nodes_), std::end(nodes_),
                                    [&tmp] (const std::unique_ptr<Node>& node) {
                                      return tmp == *node;
                                    });

  if (it_node == std::end(nodes_)) {
    LIEF_ERR("Unable to find the node");
  }

   nodes_.erase(it_node);
}


Node& Handler::create(uint64_t offset, uint64_t size, Node::Type type) {
  nodes_.push_back(std::make_unique<Node>(offset, size, type));
  return *nodes_.back();
}


Node& Handler::add(const Node& node) {
  nodes_.push_back(std::make_unique<Node>(node));
  return *nodes_.back();
}

ok_error_t Handler::make_hole(uint64_t offset, uint64_t size) {
  auto res = reserve(offset, size);
  if (!res) {
    return res.error();
  }
  data_.insert(std::begin(data_) + offset, size, 0);
  return ok();
}


ok_error_t Handler::reserve(uint64_t offset, uint64_t size) {
  const bool must_resize = data_.size() < (offset + size);
  if (!must_resize) {
    return ok();
  }

  try {
    data_.resize(offset + size, 0);
  } catch (const std::bad_alloc&) {
    return make_error_code(lief_errors::data_too_large);
  }
  return ok();
}


} // namespace DataHandler
} // namespace ELF
} // namespace LIEF
