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
#include <iomanip>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <functional>

#include <locale>
#include <iterator>
#include <iostream>
#include <string>
#include <numeric>

#include <spdlog/fmt/fmt.h>

#include "LIEF/utils.hpp"
#include "third-party/utfcpp.hpp"

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

std::string u16tou8(const std::u16string& string, bool remove_null_char) {
  std::string name;

  std::u16string clean_string;
  std::copy_if(std::begin(string), std::end(string),
               std::back_inserter(clean_string),
              utf8::internal::is_code_point_valid<char16_t>);

  utf8::unchecked::utf16to8(std::begin(clean_string), std::end(clean_string),
                            std::back_inserter(name));

  if (remove_null_char) {
    return std::string{name.c_str()};
  }
  return name;
}

std::u16string u8tou16(const std::string& string) {
  std::u16string name;
  utf8::utf8to16(std::begin(string), std::end(string), std::back_inserter(name));
  return name;
}

std::string hex_str(uint8_t c) {
  std::stringstream ss;
  ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(c);
  return ss.str();
}

std::string hex_dump(const std::vector<uint8_t>& data, const std::string& sep) {

  std::string hexstring = std::accumulate(std::begin(data), std::end(data), std::string{},
     [sep] (const std::string& a, uint8_t b) {
         return a.empty() ? fmt::format("{:02x}", b) : a + sep + fmt::format("{:02x}", b);
     });

  return hexstring;
}


bool is_printable(const std::string& str) {
  return std::all_of(std::begin(str), std::end(str),
                     [] (char c) { return std::isprint<char>(c, std::locale("C")); });
}

bool is_hex_number(const std::string& str) {
  return std::all_of(std::begin(str), std::end(str), isxdigit);
}



} // namespace LIEF
