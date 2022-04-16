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
#include <iterator>
#include <iostream>
#include "LIEF/iostream.hpp"

namespace LIEF {
vector_iostream::vector_iostream() = default;
vector_iostream::vector_iostream(bool endian_swap) :
  endian_swap_{endian_swap}
{}

size_t vector_iostream::uleb128_size(uint64_t value) {
  size_t size = 0;
  do {
    value >>= 7;
    size += sizeof(int8_t);
  } while(value != 0);
  return size;
}

size_t vector_iostream::sleb128_size(int64_t value) {
  size_t size = 0;
  int sign = value >> (8 * sizeof(value) - 1);
  bool is_more;
  do {
    size_t byte = value & 0x7F;
    value >>= 7;
    is_more = value != sign || ((byte ^ sign) & 0x40) != 0;
    size += sizeof(int8_t);
  } while (is_more);
  return size;
}


void vector_iostream::reserve(size_t size) {
  raw_.reserve(size);
}
vector_iostream& vector_iostream::put(uint8_t c) {

  if (raw_.size() < (static_cast<size_t>(tellp()) + 1)) {
    raw_.resize(static_cast<size_t>(tellp()) + 1);
  }
  raw_[tellp()] = c;
  current_pos_ += 1;
  return *this;
}
vector_iostream& vector_iostream::write(const uint8_t* s, std::streamsize n) {
  const auto pos = static_cast<size_t>(tellp());
  if (raw_.size() < (pos + n)) {
    raw_.resize(pos + n);
  }

  auto it = std::begin(raw_);
  std::advance(it, pos);
  std::copy(s, s + n, it);

  current_pos_ += n;
  return *this;
}

vector_iostream& vector_iostream::write(std::vector<uint8_t> s) {
  const auto pos = static_cast<size_t>(tellp());
  if (raw_.size() < (pos + s.size())) {
    raw_.resize(pos + s.size());
  }

  auto it = std::begin(raw_);
  std::advance(it, pos);
  std::move(std::begin(s), std::end(s), it);

  current_pos_ += s.size();
  return *this;
}

vector_iostream& vector_iostream::write(span<const uint8_t> s) {
  return write(s.data(), s.size());
}

vector_iostream& vector_iostream::write_sized_int(uint64_t value, size_t size) {
  const uint64_t stack_val = value;
  return write(reinterpret_cast<const uint8_t*>(&stack_val), size);
}

vector_iostream& vector_iostream::write(const std::string& s) {
  const auto pos = static_cast<size_t>(tellp());
  if (raw_.size() < (pos + s.size() + 1)) {
    raw_.resize(pos + s.size() + 1);
  }

  auto it = std::begin(raw_);
  std::advance(it, pos);
  std::copy(std::begin(s), std::end(s), it);

  current_pos_ += s.size() + 1;
  return *this;
}


vector_iostream& vector_iostream::write_uleb128(uint64_t value) {
  uint8_t byte;
  do {
    byte = value & 0x7F;
    value &= ~0x7F;
    if (value != 0) {
      byte |= 0x80;
    }
    write<uint8_t>(byte);
    value = value >> 7;
  } while (byte >= 0x80);

  return *this;
}

vector_iostream& vector_iostream::write_sleb128(int64_t value) {

  bool is_neg = (value < 0);
  uint8_t byte;
  bool more;
  do {
    byte = value & 0x7F;
    value = value >> 7;

    if (is_neg) {
      more = ((value != -1) || ((byte & 0x40) == 0));
    } else {
      more = ((value != 0) || ((byte & 0x40) != 0));
    }
    if (more) {
      byte |= 0x80;
    }
    write<uint8_t>(byte);
  } while (more);

  return *this;
}


vector_iostream& vector_iostream::get(std::vector<uint8_t>& c) {
  c = raw_;
  return *this;
}

vector_iostream& vector_iostream::move(std::vector<uint8_t>& c) {
  c = std::move(raw_);
  return *this;
}

vector_iostream& vector_iostream::flush() {
  return *this;
}

const std::vector<uint8_t>& vector_iostream::raw() const {
  return raw_;
}

std::vector<uint8_t>& vector_iostream::raw() {
  return raw_;
}

size_t vector_iostream::size() const {
  return raw_.size();
}

// seeks:
vector_iostream::pos_type vector_iostream::tellp() {
  return current_pos_;
}
vector_iostream& vector_iostream::seekp(vector_iostream::pos_type p) {
  current_pos_ = p;
  return *this;
}
vector_iostream& vector_iostream::seekp(vector_iostream::off_type p, std::ios_base::seekdir dir) {
  switch (dir) {
    case std::ios_base::beg:
      {
        current_pos_ = p;
        break;
      }


    case std::ios_base::end:
      {
        //current_pos_ = p;
        break;
      }


    case std::ios_base::cur:
      {
        current_pos_ += p;
        break;
      }

    default:
      {
        break;
      }
  }

  return *this;
}

vector_iostream& vector_iostream::align(size_t alignment, uint8_t fill) {
  if (raw_.size() % alignment == 0) {
    return *this;
  }

  while (raw_.size() % alignment != 0) {
    write<uint8_t>(fill);
  }

  return *this;
}


void vector_iostream::set_endian_swap(bool swap) {
  endian_swap_ = swap;
}

vector_iostream& vector_iostream::write(size_t count, uint8_t value) {
  raw_.insert(std::end(raw_), count, value);
  current_pos_ += count;
  return *this;
}


vector_iostream& vector_iostream::write(const vector_iostream& other) {
  return write(other.raw());
}



}

