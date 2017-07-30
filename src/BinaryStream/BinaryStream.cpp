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
#include "LIEF/BinaryStream/BinaryStream.hpp"

BinaryStream::~BinaryStream(void) = default;


std::pair<uint64_t, uint64_t> BinaryStream::read_uleb128(uint64_t offset) const {
  uint64_t value = 0;
  unsigned shift = 0;
  uint64_t current_offset = offset - sizeof(uint8_t);
  do {
    current_offset += sizeof(uint8_t);
    value += static_cast<uint64_t>(this->read_integer<uint8_t>(current_offset) & 0x7f) << shift;
    shift += 7;
  } while (this->read_integer<uint8_t>(current_offset) >= 128);

  uint64_t delta = current_offset - offset;
  delta++;
  return {value, delta};
}


std::pair<int64_t, uint64_t> BinaryStream::read_sleb128(uint64_t offset) const {
  int64_t  value = 0;
  unsigned shift = 0;
  uint64_t current_offset = offset - sizeof(uint8_t);
  do {
    current_offset += sizeof(uint8_t);
    value += static_cast<uint64_t>(this->read_integer<uint8_t>(current_offset) & 0x7f) << shift;
    shift += 7;
  } while (this->read_integer<uint8_t>(current_offset) >= 128);


  // Sign extend
  if ((value & 0x40) != 0) {
    value |= static_cast<int64_t>(-1) << shift;
  }

  uint64_t delta = current_offset - offset;
  delta++;

  return {value, delta};
}

