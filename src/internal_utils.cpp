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
#include "internal_utils.hpp"
namespace LIEF {

inline bool is_printable(char c) {
  return ::isprint(c) && c != '\n' && c != '\r';
}

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
}  // namespace LIEF
