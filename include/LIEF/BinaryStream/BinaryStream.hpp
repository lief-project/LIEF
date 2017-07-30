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
#ifndef LIEF_BINARY_STREAM_H_
#define LIEF_BINARY_STREAM_H_

#include <stdint.h>
#include <climits>
#include <vector>
#include <istream>
#include <utility>

class BinaryStream {
  public:
    virtual ~BinaryStream();
    virtual uint64_t    size(void)                                  const = 0;
    virtual const void* read(uint64_t offset, uint64_t size)        const = 0;
    virtual const char* read_string(uint64_t offset, uint64_t size) const = 0;

    template<typename T>
    T read_integer(uint64_t offset, bool swap = false) const;

    std::pair<uint64_t, uint64_t> read_uleb128(uint64_t offset) const;
    std::pair<int64_t, uint64_t>  read_sleb128(uint64_t offset) const;

    template<typename T>
    static T swap_endian(T u);
};


template<typename T>
T BinaryStream::read_integer(uint64_t offset, bool swap) const {
  static_assert(std::is_integral<T>::value, "Interger required");
  const T* value = reinterpret_cast<const T*>(this->read(offset, sizeof(T)));
  return swap ? swap_endian(*value) : *value;
}


template<typename T>
T BinaryStream::swap_endian(T u) {
  // From http://stackoverflow.com/a/4956493
  static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");
  static_assert(std::is_integral<T>::value, "Interger required");
  union {
    T u;
    unsigned char u8[sizeof(T)];
  } source, dest;

  source.u = u;

  for (size_t k = 0; k < sizeof(T); k++) {
    dest.u8[k] = source.u8[sizeof(T) - k - 1];
  }

  return dest.u;
}



#endif
