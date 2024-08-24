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
#include "internal_utils.hpp"
namespace LIEF {

std::string printable_string(const std::string& str) {
  std::string out;
  out.reserve(str.size());
  for (char c : str) {
    if (is_printable(c)) {
      out += c;
    }
  }
  return out;
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

inline std::string pretty_hex(char c) {
  if (is_printable(c)) {
    return std::string("") + c;
  }
  return ".";
}

std::string dump(const uint8_t* buffer, size_t size,
                 const std::string& title, const std::string& prefix, size_t limit)
{

  std::string out;
  std::string banner;

  if (!title.empty()) {
    banner  = prefix + "+" + std::string(22 * 3, '-') + "---+" + "\n" + prefix + "| ";
    banner += title;
    banner += std::string(68 - title.size(), ' ') + "|\n";
  }

  out = std::string(22 * 3, '-') + "\n";
  std::string lhs, rhs;
  if (limit > 0) {
    size = std::min<size_t>(size, limit);
  }
  for (size_t i = 0; i < size; ++i) {
    if (i == 0) {
      out = prefix + "+" + std::string(22 * 3, '-') + "---+" + "\n" + prefix + "| ";
    }

    if (i > 0 && i % 16 == 0) {
      out += "\n" + prefix + "| ";
    }

    rhs += pretty_hex((char)(buffer[i]));
    out += fmt::format("{:02x} ", buffer[i]);

    if (i % 16 == 15 || i == (size - 1)) {
      if (i == (size - 1)) {
        out += std::string(((16 - ((size - 1) % 16) - 1)) * 3, ' ');
        rhs += std::string(((16 - ((size - 1) % 16) - 1)) * 1, ' ');
      }
      out += " | ";
      out += rhs + " |";
      rhs = "";
    }

  }

  out += std::string("\n") + prefix + "+" + std::string(22 * 3, '-') + "---+";
  return banner + out;
}

}
