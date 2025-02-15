/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"

#include "LIEF/PE/resources/ResourceVar.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceVar>(nb::module_& m) {
  nb::class_<ResourceVar> obj(m, "ResourceVar",
    R"doc(
    This class represents an element of the :class:`~.ResourceVarFileInfo` structure
    It typically contains a list of language and code page identifier pairs that
    the version of the application or DLL supports.

    See: https://learn.microsoft.com/en-us/windows/win32/menurc/var-str
    )doc"_doc
  );
  obj
    .def_prop_ro("type", nb::overload_cast<>(&ResourceVar::type, nb::const_),
      R"doc(
      The type of data in the version resource:
        * ``1`` if it contains text data
        * ``0`` if it contains binary data
      )doc"_doc
    )
    .def_prop_ro("key", nb::overload_cast<>(&ResourceVar::key_u8, nb::const_),
      R"doc(Signature of the structure. Must be the unicode string "Translation")doc"_doc
    )

    .def_prop_ro("values", nb::overload_cast<>(&ResourceVar::values, nb::const_),
      R"doc(
      Return the translation values.

      The low-order word of each uint32_t must contain a Microsoft language
      identifier, and the high-order word must contain the IBM code page number.
      Either high-order or low-order word can be zero, indicating that the file
      is language or code page independent
      )doc"_doc
    )

    LIEF_DEFAULT_STR(ResourceVar);
}

}

