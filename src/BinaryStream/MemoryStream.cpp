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
#include "logging.hpp"

#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/BinaryStream/MemoryStream.hpp"
#include "LIEF/utils.hpp"

namespace LIEF {

static constexpr uint64_t MAX_MEM_SIZE = 6_GB;

MemoryStream::MemoryStream(MemoryStream&&) = default;
MemoryStream& MemoryStream::operator=(MemoryStream&&) = default;

MemoryStream::MemoryStream(uintptr_t base_address) :
  baseaddr_{base_address},
  size_{MAX_MEM_SIZE}
{
  stype_ = STREAM_TYPE::MEMORY;
}

MemoryStream::MemoryStream(uintptr_t base_address, uint64_t size) :
  baseaddr_{base_address},
  size_{size}
{
  stype_ = STREAM_TYPE::MEMORY;
}

uint64_t MemoryStream::size() const {
  return size_;
}

result<const void*> MemoryStream::read_at(uint64_t offset, uint64_t size) const {
  if (offset > size_ || (offset + size) > size_) {
    return make_error_code(lief_errors::read_out_of_bound);
  }

  const uintptr_t va = baseaddr_ + offset;
  if (binary_ != nullptr) {
    if (auto res = binary_->offset_to_virtual_address(offset, baseaddr_)) {
      return reinterpret_cast<const void*>(*res);
    }
  }
  return reinterpret_cast<const void*>(va);
}

bool MemoryStream::classof(const BinaryStream& stream) {
  return stream.type() == STREAM_TYPE::MEMORY;
}

MemoryStream::~MemoryStream() = default;

}

