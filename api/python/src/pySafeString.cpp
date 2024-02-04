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
#include "pySafeString.hpp"
#include "pyLIEF.hpp"

namespace LIEF::py {
safe_string_t safe_string(const std::string& str) {
  nb::bytes str_bytes(str.c_str(), str.size());
  try {
    return nb::str(str_bytes.attr("decode")("utf8"));
  } catch (const std::exception& e) {
    return str_bytes;
  }
}
}
