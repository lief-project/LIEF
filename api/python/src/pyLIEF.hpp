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
#ifndef PY_LIEF_H
#define PY_LIEF_H

#include <nanobind/nanobind.h>

#define RST_CLASS_REF(X) ":class:`~"#X"`"
#define RST_CLASS_REF_FULL(X) ":class:`"#X"`"

#define RST_ATTR_REF(X) ":attr:`~"#X"`"
#define RST_ATTR_REF_FULL(X) ":attr:`"#X"`"

#define RST_METH_REF(X) ":class:`~"#X"`"
#define RST_METH_REF_FULL(X) ":class:`"#X"`"

#define LIEF_MOD_NAME "lief"

#define LIEF_DEFAULT_STR(OBJ)        \
    .def("__str__",                  \
        [] (const OBJ& O) {          \
          std::ostringstream stream; \
          stream << O;               \
          return stream.str();       \
        })

#define LIEF_COPYABLE(OBJ) \
    .def("copy", [] (OBJ& self) { return OBJ(self); },       \
        "Duplicate the current instance of this object"_doc, \
        nb::rv_policy::move)

#define LIEF_CLONABLE(OBJ) \
    .def("copy", [] (OBJ& self) {return self.clone(); },    \
        "Duplicate the current instance of this object"_doc, \
        nb::rv_policy::take_ownership)

constexpr const char* operator "" _doc(const char* value, size_t) {
  return value;
}

namespace nb = nanobind;

extern nb::module_* lief_mod;

using namespace nb::literals;

#endif
