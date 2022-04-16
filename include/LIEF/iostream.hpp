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
#ifndef LIEF_OSTREAM_H_
#define LIEF_OSTREAM_H_
#include <istream>
#include <streambuf>
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

#include "LIEF/span.hpp"
#include "LIEF/BinaryStream/Convert.hpp"

namespace LIEF {
class vector_iostream {
  public:
  static size_t uleb128_size(uint64_t value);
  static size_t sleb128_size(int64_t value);
  using pos_type = std::streampos;
  using off_type = std::streamoff;
  vector_iostream();
  vector_iostream(bool endian_swap);
  void reserve(size_t size);

  vector_iostream& put(uint8_t c);
  vector_iostream& write(const uint8_t* s, std::streamsize n);
  vector_iostream& write(span<const uint8_t> sp);
  vector_iostream& write(std::vector<uint8_t> s);
  vector_iostream& write(const std::string& s);
  vector_iostream& write(size_t count, uint8_t value);
  vector_iostream& write_sized_int(uint64_t value, size_t size);
  vector_iostream& write(const vector_iostream& other);

  template<class T, typename U = typename std::enable_if<!std::is_integral<T>::value>, T>
  vector_iostream& write(const U& t) {
    const auto pos = static_cast<size_t>(tellp());
    if (raw_.size() < (pos + sizeof(T))) {
      raw_.resize(pos + sizeof(T));
    }
    memcpy(raw_.data() + pos, &t, sizeof(T));
    current_pos_ += sizeof(T);
    return *this;
  }

  template<typename T>
  vector_iostream& write_conv(const T& t);

  template<typename T>
  vector_iostream& write_conv_array(const std::vector<T>& v);

  vector_iostream& align(size_t alignment, uint8_t fill = 0);

  template<class Integer, typename = typename std::enable_if<std::is_integral<Integer>::value>>
  vector_iostream& write(Integer integer) {
    const auto pos = static_cast<size_t>(tellp());
    if (raw_.size() < (pos + sizeof(Integer))) {
      raw_.resize(pos + sizeof(Integer));
    }
    memcpy(raw_.data() + pos, &integer, sizeof(Integer));
    current_pos_ += sizeof(Integer);
    return *this;
  }

  template<typename T, size_t size, typename = typename std::enable_if<std::is_integral<T>::value>>
  vector_iostream& write(const std::array<T, size>& t) {
    for (T val : t) {
      write<T>(val);
    }
    return *this;
  }


  template<typename T>
  vector_iostream& write(const std::vector<T>& elements) {
    for (const T& e : elements) {
      write(e);
    }
    return *this;
  }

  vector_iostream& write_uleb128(uint64_t value);
  vector_iostream& write_sleb128(int64_t value);

  vector_iostream& get(std::vector<uint8_t>& c);
  vector_iostream& move(std::vector<uint8_t>& c);

  vector_iostream& flush();

  size_t size() const;

  // seeks:
  pos_type tellp();
  vector_iostream& seekp(pos_type p);
  vector_iostream& seekp(vector_iostream::off_type p, std::ios_base::seekdir dir);

  const std::vector<uint8_t>& raw() const;
  std::vector<uint8_t>& raw();

  void set_endian_swap(bool swap);

  private:
  pos_type             current_pos_ = 0;
  std::vector<uint8_t> raw_;
  bool                 endian_swap_ = false;
};


template<typename T>
vector_iostream& vector_iostream::write_conv(const T& t) {
  const uint8_t *ptr = nullptr;
  T tmp = t;
  if (endian_swap_) {
    LIEF::Convert::swap_endian<T>(&tmp);
    ptr = reinterpret_cast<const uint8_t*>(&tmp);
  } else {
    ptr = reinterpret_cast<const uint8_t*>(&t);
  }
  write(ptr, sizeof(T));
  return *this;
}

template<typename T>
vector_iostream& vector_iostream::write_conv_array(const std::vector<T>& v) {
  for (const T& i: v) {
    const uint8_t* ptr = nullptr;
    T tmp = i;
    if (endian_swap_) {
      LIEF::Convert::swap_endian<T>(&tmp);
      ptr = reinterpret_cast<const uint8_t*>(&tmp);
    } else {
      ptr = reinterpret_cast<const uint8_t*>(&i);
    }
    write(ptr, sizeof(T));
  }
  return *this;
}


}
#endif
