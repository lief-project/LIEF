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
#ifndef LIEF_OSTREAM_H_
#define LIEF_OSTREAM_H_
#include <istream>
#include <streambuf>
#include <cstdint>
#include <vector>

#include "LIEF/BinaryStream/Convert.hpp"

namespace LIEF {
class vector_iostream {
  public:
  static size_t uleb128_size(uint64_t value);
  static size_t sleb128_size(int64_t value);
  using pos_type = std::streampos;
  using off_type = std::streamoff;

  vector_iostream(bool endian_swap=false);
  void reserve(size_t size);

  vector_iostream& put(uint8_t c);
  vector_iostream& write(const uint8_t* s, std::streamsize n);
  vector_iostream& write(const std::vector<uint8_t>& s);
  vector_iostream& write(std::vector<uint8_t>&& s);
  vector_iostream& write(const std::string& s);
  vector_iostream& write(size_t count, uint8_t value);

  template<typename T>
  vector_iostream& write_conv(const T& t);

  template<typename T>
  vector_iostream& write_conv_array(const std::vector<T>& v);

  vector_iostream& align(size_t size, uint8_t val = 0);

  template<class Integer, typename = typename std::enable_if<std::is_integral<Integer>::value>>
  vector_iostream& write(Integer integer) {
    if (this->raw_.size() < (static_cast<size_t>(this->tellp()) + sizeof(Integer))) {
      this->raw_.resize(static_cast<size_t>(this->tellp()) + sizeof(Integer));
    }

    auto&& it = std::begin(this->raw_);
    std::advance(it, static_cast<size_t>(this->tellp()));
    std::copy(
        reinterpret_cast<const Integer*>(&integer),
        reinterpret_cast<const Integer*>(&integer) + sizeof(Integer),
        it);

    this->current_pos_ += sizeof(Integer);
    return *this;
  }

  vector_iostream& write_uleb128(uint64_t value);
  vector_iostream& write_sleb128(int64_t value);

  vector_iostream& get(std::vector<uint8_t>& c);

  vector_iostream& flush();

  size_t size(void) const;

  // seeks:
  pos_type tellp(void);
  vector_iostream& seekp(pos_type p);
  vector_iostream& seekp(vector_iostream::off_type p, std::ios_base::seekdir dir);

  const std::vector<uint8_t>& raw(void) const;
  std::vector<uint8_t>& raw(void);

  void set_endian_swap(bool swap);

  private:
  pos_type             current_pos_;
  std::vector<uint8_t> raw_;
  bool                 endian_swap_{false};
};


template<typename T>
vector_iostream& vector_iostream::write_conv(const T& t) {
  const uint8_t *ptr = nullptr;
  T tmp = t;
  if (this->endian_swap_) {
    LIEF::Convert::swap_endian<T>(&tmp);
    ptr = reinterpret_cast<const uint8_t*>(&tmp);
  } else {
    ptr = reinterpret_cast<const uint8_t*>(&t);
  }
  this->write(ptr, sizeof(T));
  return *this;
}

template<typename T>
vector_iostream& vector_iostream::write_conv_array(const std::vector<T>& v) {
  for (const T& i: v) {
    const uint8_t* ptr = nullptr;
    T tmp = i;
    if (this->endian_swap_) {
      LIEF::Convert::swap_endian<T>(&tmp);
      ptr = reinterpret_cast<const uint8_t*>(&tmp);
    } else {
      ptr = reinterpret_cast<const uint8_t*>(&i);
    }
    this->write(ptr, sizeof(T));
  }
  return *this;
}

// From https://stackoverflow.com/questions/27336335/c-cout-with-prefix
class prefixbuf : public std::streambuf {
  public:
  prefixbuf(std::string const& prefix, std::streambuf* sbuf);

  private:
  std::string     prefix;
  std::streambuf* sbuf;
  bool            need_prefix;

  int sync(void);
  int overflow(int c);
};

class oprefixstream : private virtual prefixbuf, public std::ostream {
  public:
  oprefixstream(std::string const& prefix, std::ostream& out);
};

}
#endif
