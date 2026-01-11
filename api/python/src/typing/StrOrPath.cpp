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
#include "typing/StrOrPath.hpp"

namespace LIEF::py::typing {

std::optional<std::string> StrOrPath::to_string() {
  PyObject* buf = PyOS_FSPath(this->ptr());
  if (!buf) {
    PyErr_Clear();
    return std::nullopt;
  }

  PyObject* native = nullptr;
  std::string path_str;
  if (PyUnicode_FSConverter(buf, &native) != 0) {
    if (char* c_str = PyBytes_AsString(native)) {
      path_str = c_str;
    }
  }
  Py_XDECREF(native);
  Py_DECREF(buf);
  if (PyErr_Occurred()) {
    PyErr_Clear();
    return std::nullopt;
  }

  return path_str;
}
}
