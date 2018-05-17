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
#include "LIEF/iostream.hpp"

namespace LIEF {
vector_iostream::vector_iostream(bool endian_swap) : endian_swap_{endian_swap} {}

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
  size_t sz = s.size() + 1;
  if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + sz)) {
    this->raw_.resize(static_cast<size_t>(this->tellp()) + sz);
  }
  auto&& it = std::begin(this->raw_);
  std::advance(it, static_cast<size_t>(this->tellp()));
  std::move(
      std::begin(s),
      std::end(s), it);
  this->raw_.push_back(0);

  this->current_pos_ += sz;
  return *this;
}

vector_iostream& vector_iostream::align(size_t align_on, uint8_t val) {
  if (not(align_on == 0 or (this->current_pos_ % align_on) == 0)) {
    size_t sz = this->raw_.size();
    size_t new_sz = ((sz - 1) / align_on + 1) * align_on; 
    this->raw_.resize(new_sz, val);
    this->current_pos_ = new_sz;
  }
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



}

