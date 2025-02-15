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

#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"
#include "LIEF/PE/resources/ResourceStringTable.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/u16string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceStringFileInfo>(nb::module_& m) {
  nb::class_<ResourceStringFileInfo, LIEF::Object> obj(m, "ResourceStringFileInfo",
      R"delim(
      Representation of the ``StringFileInfo`` structure

      See: https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
      )delim"_doc);

  LIEF::py::init_ref_iterator<ResourceStringFileInfo::it_elements>(obj, "it_elements");

  obj
    .def_prop_ro("type", nb::overload_cast<>(&ResourceStringFileInfo::type, nb::const_),
      R"doc(
      The type of data in the version resource:
        * ``1`` if it contains text data
        * ``0`` if it contains binary data
      )doc"_doc
    )

    .def_prop_ro("key", nb::overload_cast<>(&ResourceStringFileInfo::key_u8, nb::const_),
      R"doc(Signature of the structure. Must be the unicode string "StringFileInfo")doc"_doc
    )

    .def_prop_ro("children", nb::overload_cast<>(&ResourceStringFileInfo::children),
      "Iterator over the children values"_doc
    )

    LIEF_DEFAULT_STR(ResourceStringFileInfo);
}
}

