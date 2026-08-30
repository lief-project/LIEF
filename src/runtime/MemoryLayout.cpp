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

// NOLINTBEGIN
#include "LIEF/runtime/MemoryLayout.hpp"
#include "internal_utils.hpp"
#include "logging.hpp"
#include "messages.hpp"

namespace LIEF::runtime {

namespace details {
class MemoryLayoutIt {};
}

MemoryLayout::Iterator::Iterator() :
  impl_(nullptr) {}

MemoryLayout::Iterator::Iterator(const MemoryLayout::Iterator&) :
  impl_(nullptr) {}

MemoryLayout::Iterator&
    MemoryLayout::Iterator::operator=(const MemoryLayout::Iterator&) {
  return *this;
}

MemoryLayout::Iterator::Iterator(MemoryLayout::Iterator&&) noexcept :
  impl_(nullptr) {}

MemoryLayout::Iterator&
    MemoryLayout::Iterator::operator=(MemoryLayout::Iterator&&) noexcept {
  return *this;
}

MemoryLayout::Iterator::
    Iterator(std::unique_ptr<details::MemoryLayoutIt> /*impl*/) :
  impl_(nullptr) {}

MemoryLayout::Iterator::~Iterator() = default;

bool operator==(const MemoryLayout::Iterator& /*LHS*/,
                const MemoryLayout::Iterator& /*RHS*/) {
  return true;
}

MemoryLayout::Iterator& MemoryLayout::Iterator::operator++() {
  return *this;
}

const MemoryLayout::Region& MemoryLayout::Iterator::operator*() const {
  return *cached_;
}

const MemoryLayout::Region* MemoryLayout::Iterator::operator->() const {
  return nullptr;
}

std::unique_ptr<MemoryLayout::Region> MemoryLayout::Iterator::yield() {
  return nullptr;
}

void MemoryLayout::Iterator::load() const {
  return;
}

std::string MemoryLayout::Region::to_string() const {
  return "";
}

memory_layout_it memory_layout() {
  LIEF_ERR(NEEDS_EXTENDED_MSG);
  return make_empty_iterator<MemoryLayout>();
}

// NOLINTEND

}
