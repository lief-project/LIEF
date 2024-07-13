/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <algorithm>
#include <iomanip>
#include <iterator>
#include <locale>
#include <numeric>
#include <sstream>
#include <string>

#include <spdlog/fmt/fmt.h>

#include "LIEF/utils.hpp"
#include "LIEF/errors.hpp"

#include "third-party/utfcpp.hpp"

#include "LIEF/config.h"

namespace LIEF {
namespace LEB128 {
std::vector<uint8_t> uencode(uint64_t value) {
  std::vector<uint8_t> result;
  do {
    uint8_t b = value & 0x7F;
    value >>= 7;
    if (value > 0) {
      b |= 0x80;
    }
    result.push_back(b);
  } while (value != 0);
  return result;
}

}


template <typename octet_iterator>
result<uint32_t> next(octet_iterator& it, octet_iterator end) {
  using namespace utf8;
  utfchar32_t cp = 0;
  internal::utf_error err_code = internal::validate_next(it, end, cp);
  switch (err_code) {
    case internal::UTF8_OK :
      break;
    case internal::NOT_ENOUGH_ROOM :
      return make_error_code(lief_errors::data_too_large);
    case internal::INVALID_LEAD :
    case internal::INCOMPLETE_SEQUENCE :
    case internal::OVERLONG_SEQUENCE :
      return make_error_code(lief_errors::read_error);
    case internal::INVALID_CODE_POINT :
      return make_error_code(lief_errors::read_error);
  }
  return cp;
}

std::string u16tou8(const std::u16string& string, bool remove_null_char) {
  std::string name;

  std::u16string clean_string;
  std::copy_if(std::begin(string), std::end(string),
               std::back_inserter(clean_string),
               utf8::internal::is_code_point_valid);

  utf8::unchecked::utf16to8(std::begin(clean_string), std::end(clean_string),
                            std::back_inserter(name));

  if (remove_null_char) {
    return std::string{name.c_str()};
  }
  return name;
}

result<std::u16string> u8tou16(const std::string& string) {
  std::u16string name;
  auto start = string.begin();
  auto end   = string.end();
  auto res   = std::back_inserter(name);
  while (start < end) {
    auto cp = next(start, end);
    if (!cp) {
      return make_error_code(lief_errors::conversion_error);
    }
    uint32_t cp_val = *cp;
    if (cp_val > 0xffff) {
      *res++ = static_cast<uint16_t>((cp_val >> 10)   + utf8::internal::LEAD_OFFSET);
      *res++ = static_cast<uint16_t>((cp_val & 0x3ff) + utf8::internal::TRAIL_SURROGATE_MIN);
    } else {
      *res++ = static_cast<uint16_t>(cp_val);
    }
  }
  return name;
}

std::string hex_str(uint8_t c) {
  std::stringstream ss;
  ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(c);
  return ss.str();
}

template<class T>
std::string hex_dump_impl(T data, const std::string& sep) {
  std::vector<std::string> hexdigits;
  hexdigits.reserve(data.size());
  std::transform(data.begin(), data.end(), std::back_inserter(hexdigits),
                 [] (uint8_t x) { return fmt::format("{:02x}", x); });
  return fmt::to_string(fmt::join(hexdigits, sep));
}

std::string hex_dump(const std::vector<uint8_t>& data, const std::string& sep) {
  return hex_dump_impl(data, sep);
}

std::string hex_dump(span<const uint8_t> data, const std::string& sep) {
  return hex_dump_impl(data, sep);
}


bool is_hex_number(const std::string& str) {
  return std::all_of(std::begin(str), std::end(str), isxdigit);
}


bool is_extended() {
  return lief_extended;
}


} // namespace LIEF
