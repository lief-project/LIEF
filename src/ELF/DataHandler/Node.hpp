/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_ELF_DATA_HANDLER_NODE_H
#define LIEF_ELF_DATA_HANDLER_NODE_H

#include <cstdint>
#include "LIEF/visibility.h"

namespace LIEF::ELF::DataHandler {

class LIEF_LOCAL Node {
  public:
  enum Type : uint8_t {
    UNKNOWN = 0,
    SECTION,
    SEGMENT,
  };
  using owner_invalidator_t = void (*)(void* owner, Node& node) noexcept;

  Node() = default;
  Node(uint64_t offset, uint64_t size, Type type) :
    size_{size},
    offset_{offset},
    type_{type} {}

  Node& operator=(const Node& other) noexcept {
    if (this == &other) {
      return *this;
    }

    size_ = other.size_;
    offset_ = other.offset_;
    type_ = other.type_;
    return *this;
  }

  Node(const Node& other) noexcept :
    size_{other.size_},
    offset_{other.offset_},
    type_{other.type_} {}

  uint64_t size() const {
    return size_;
  }
  uint64_t offset() const {
    return offset_;
  }

  Type type() const {
    return type_;
  }

  void size(uint64_t size) {
    size_ = size;
  }

  void type(Type type) {
    type_ = type;
  }

  void offset(uint64_t offset) {
    offset_ = offset;
  }

  void bind_owner(void* owner, owner_invalidator_t invalidator) noexcept {
    assert(owner != nullptr);
    assert(invalidator != nullptr);
    assert(owner_ == nullptr);
    assert(owner_invalidator_ == nullptr);

    owner_ = owner;
    owner_invalidator_ = invalidator;
  }

  void rebind_owner(void* owner) noexcept {
    assert(owner != nullptr);
    assert(owner_ != nullptr);
    assert(owner_invalidator_ != nullptr);

    owner_ = owner;
  }

  bool has_owner() const noexcept {
    return owner_ != nullptr;
  }

  bool operator==(const Node& rhs) const;
  bool operator!=(const Node& rhs) const {
    return !(*this == rhs);
  }

  bool operator<(const Node& rhs) const;
  bool operator<=(const Node& rhs) const {
    return (type() == rhs.type() && !(*this > rhs));
  }

  bool operator>(const Node& rhs) const;
  bool operator>=(const Node& rhs) const {
    return (type() == rhs.type() && !(*this < rhs));
  }
  ~Node() {
    invalidate_owner();
  }

  private:
  void invalidate_owner() noexcept {
    void* owner = owner_;
    owner_invalidator_t invalidator = owner_invalidator_;

    // clear first to avoid callback recursion
    owner_ = nullptr;
    owner_invalidator_ = nullptr;

    if (invalidator != nullptr) {
      invalidator(owner, *this);
    }
  }

  uint64_t size_ = 0;
  uint64_t offset_ = 0;
  Type type_ = Type::UNKNOWN;

  void* owner_ = nullptr;
  owner_invalidator_t owner_invalidator_ = nullptr;
};

} // namespace LIEF::ELF::DataHandler

#endif
