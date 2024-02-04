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
#ifndef PY_LIEF_SAFE_STRING_H
#define PY_LIEF_SAFE_STRING_H
#include <string>
#include "typing.hpp"

struct safe_string_t : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(safe_string_t, nanobind::str);
  LIEF_PY_DEFAULT_CTOR(safe_string_t, nanobind::bytes);

  NB_OBJECT_DEFAULT(safe_string_t, object, "Union[str, bytes]", check)

  static bool check(handle h) {
    return true;
  }
};

namespace LIEF::py {
safe_string_t safe_string(const std::string& str);
}
#endif
