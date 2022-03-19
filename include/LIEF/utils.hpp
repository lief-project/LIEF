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
#ifndef LIEF_UTILS_HEADER
#define LIEF_UTILS_HEADER
#include <string>
#include <vector>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
inline uint64_t align(uint64_t value, uint64_t align_on) {
  if (align_on == 0) {
    return value;
  }
  const auto r = value % align_on;
  if (r > 0) {
    return value + (align_on - r);
  }
  return value;
}

template <typename T>
inline constexpr T round(T x) {
  return static_cast<T>(round<uint64_t>(x));
}

template <>
inline uint64_t round<uint64_t>(uint64_t x) {
  // From http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
  x--;
  x |= x >> 1;   // handle  2 bit numbers
  x |= x >> 2;   // handle  4 bit numbers
  x |= x >> 4;   // handle  8 bit numbers
  x |= x >> 8;   // handle 16 bit numbers
  x |= x >> 16;  // handle 32 bit numbers
  x |= x >> 32;  // handle 64 bit numbers
  x++;
  return x;
}

constexpr size_t operator""_KB(unsigned long long kbs) { return 1024 * kbs; }

constexpr size_t operator""_MB(unsigned long long mbs) {
  return 1024 * 1024 * mbs;
}

constexpr size_t operator""_GB(unsigned long long gbs) {
  return 1024 * 1024 * 1024 * gbs;
}

//! @brief Convert a UTF-16 string to a UTF-8 one
LIEF_API std::string u16tou8(const std::u16string& string,
                             bool remove_null_char = false);

//! @brief Convert a UTF-8 string to a UTF-16 one
LIEF_API std::u16string u8tou16(const std::string& string);

LIEF_API std::string hex_str(uint8_t c);

LIEF_API std::string hex_dump(const std::vector<uint8_t>& data,
                              const std::string& sep = ":");

//! Check if the given string in printable
LIEF_API bool is_printable(const std::string& str);

//! Check if the given number is a hex-like string
LIEF_API bool is_hex_number(const std::string& nb);
}  // namespace LIEF

namespace LIEF {
namespace LEB128 {
std::vector<uint8_t> uencode(uint64_t value);
}
}  // namespace LIEF

#endif
