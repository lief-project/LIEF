/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef PY_LIEF_TYPING_PATH_OR_STR_H
#define PY_LIEF_TYPING_PATH_OR_STR_H
#include "pyLIEF.hpp"
#include "typing.hpp"

#include <optional>
#include <string>

#include <nanobind/nanobind.h>


namespace LIEF::py::typing {

struct StrOrPath : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(StrOrPath, nanobind::object);

  NB_OBJECT_DEFAULT(StrOrPath, object, "Union[str, os.PathLike]", check)

  std::optional<std::string> to_string();

  static bool check(handle h) {
    PyObject* buf = PyOS_FSPath(h.ptr());
    if (buf == nullptr) {
      PyErr_Clear();
      return false;
    }
    return true;
  }
};

}
#endif
