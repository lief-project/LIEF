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
#include <iterator>
#include <iostream>
#include "LIEF/iostream.hpp"

namespace LIEF {
vector_iostream::vector_iostream(bool endian_swap) : endian_swap_{endian_swap} {}

size_t vector_iostream::uleb128_size(uint64_t value) {
  size_t size = 0;
  do {
    value >>= 7;
    size += sizeof(int8_t);
  } while(value);
  return size;
}

size_t vector_iostream::sleb128_size(int64_t value) {
  size_t size = 0;
  int sign = value >> (8 * sizeof(value) - 1);
  bool is_more;
  do {
    size_t byte = value & 0x7F;
    value >>= 7;
    is_more = value != sign or ((byte ^ sign) & 0x40) != 0;
    size += sizeof(int8_t);
  } while (is_more);
  return size;
}


void vector_iostream::reserve(size_t size) {
  this->raw_.reserve(size);
}
vector_iostream& vector_iostream::put(uint8_t c) {

  if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + 1)) {
    this->raw_.resize(static_cast<size_t>(this->tellp()) + 1);
  }
  this->raw_[this->tellp()] = c;
  this->current_pos_ += 1;
  return *this;
}
vector_iostream& vector_iostream::write(const uint8_t* s, std::streamsize n) {
  if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + n)) {
    this->raw_.resize(static_cast<size_t>(this->tellp()) + n);
  }

  auto&& it = std::begin(this->raw_);
  std::advance(it, static_cast<size_t>(this->tellp()));
  std::copy(s, s + n, it);

  this->current_pos_ += n;
  return *this;
}

vector_iostream& vector_iostream::write(const std::vector<uint8_t>& s) {
  if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + s.size())) {
    this->raw_.resize(static_cast<size_t>(this->tellp()) + s.size());
  }
  auto&& it = std::begin(this->raw_);
  std::advance(it, static_cast<size_t>(this->tellp()));
  std::copy(std::begin(s), std::end(s), it);

  this->current_pos_ += s.size();
  return *this;
}

vector_iostream& vector_iostream::write_sized_int(uint64_t value, size_t size) {
  const uint64_t stack_val = value;
  return this->write(reinterpret_cast<const uint8_t*>(&stack_val), size);
}


vector_iostream& vector_iostream::write(std::vector<uint8_t>&& s) {
  if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + s.size())) {
    this->raw_.resize(static_cast<size_t>(this->tellp()) + s.size());
  }
  auto&& it = std::begin(this->raw_);
  std::advance(it, static_cast<size_t>(this->tellp()));
  std::move(
      std::begin(s),
      std::end(s), it);

  this->current_pos_ += s.size();
  return *this;
}

vector_iostream& vector_iostream::write(const std::string& s) {
  if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + s.size() + 1)) {
    this->raw_.resize(static_cast<size_t>(this->tellp()) + s.size() + 1);
  }

  auto&& it = std::begin(this->raw_);
  std::advance(it, static_cast<size_t>(this->tellp()));
  std::copy(std::begin(s), std::end(s), it);

  this->current_pos_ += s.size() + 1;
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
    this->write<uint8_t>(byte);
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
    this->write<uint8_t>(byte);
  } while (more);

  return *this;
}


vector_iostream& vector_iostream::get(std::vector<uint8_t>& c) {
  c = this->raw_;
  return *this;
}

vector_iostream& vector_iostream::flush() {
  return *this;
}

const std::vector<uint8_t>& vector_iostream::raw(void) const {
  return this->raw_;
}

std::vector<uint8_t>& vector_iostream::raw(void) {
  return this->raw_;
}

size_t vector_iostream::size(void) const {
  return this->raw_.size();
}

// seeks:
vector_iostream::pos_type vector_iostream::tellp(void) {
  return this->current_pos_;
}
vector_iostream& vector_iostream::seekp(vector_iostream::pos_type p) {
  this->current_pos_ = p;
  return *this;
}
vector_iostream& vector_iostream::seekp(vector_iostream::off_type p, std::ios_base::seekdir dir) {
  switch (dir) {
    case std::ios_base::beg:
      {
        this->current_pos_ = p;
        break;
      }


    case std::ios_base::end:
      {
        //this->current_pos_ = p;
        break;
      }


    case std::ios_base::cur:
      {
        this->current_pos_ += p;
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
  if (this->raw_.size() % alignment == 0) {
    return *this;
  }

  while (this->raw_.size() % alignment != 0) {
    this->write<uint8_t>(fill);
  }

  return *this;
}


void vector_iostream::set_endian_swap(bool swap) {
  this->endian_swap_ = swap;
}


// Prefixbuf
prefixbuf::prefixbuf(std::string const& prefix, std::streambuf* sbuf) :
  prefix{prefix},
  sbuf{sbuf},
  need_prefix{true}
{}

int prefixbuf::sync() {
  return this->sbuf->pubsync();
}
int prefixbuf::overflow(int c) {
  if (c != std::char_traits<char>::eof()) {
    if (this->need_prefix and not this->prefix.empty() and
        this->prefix.size() != this->sbuf->sputn(&this->prefix[0], this->prefix.size())) {
      return std::char_traits<char>::eof();
    }

    this->need_prefix = c == '\n';
  }

  return this->sbuf->sputc(c);
}


oprefixstream::oprefixstream(std::string const& prefix, std::ostream& out) :
  prefixbuf(prefix, out.rdbuf()),
  std::ios(static_cast<std::streambuf*>(this)),
  std::ostream(static_cast<std::streambuf*>(this))
{}


vector_iostream& vector_iostream::write(size_t count, uint8_t value) {
    this->raw_.insert(
        std::end(this->raw_),
        /* count */ count,
        /* value */ value
    );
    this->current_pos_ += count;
    return *this;
}



}

