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

#include "LIEF/PE/resources/ResourceStringTable.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/stl/u16string.h>
#include <nanobind/extra/stl/lief_optional.h>

namespace LIEF::PE::py {

template<>
void create<ResourceStringTable>(nb::module_& m) {
  using entry_t = ResourceStringTable::entry_t;
  nb::class_<ResourceStringTable, LIEF::Object> obj(m, "ResourceStringTable",
    R"doc(
    This class represents the ``StringTable`` structure. This structure
    can be seen as a dictionary of key, values with key and values defined a
    utf-16 string.
    )doc"_doc
  );

  LIEF::py::init_ref_iterator<ResourceStringTable::it_entries>(obj, "it_entries");

  nb::class_<entry_t>(obj, "entry_t",
    R"doc(
    An entry in this table which is composed of an UTF-16 key and an UTF-16
    value.
    )doc"_doc
  )
    .def_rw("key", &entry_t::key)
    .def_rw("value", &entry_t::value)
    .def("__bool__", &entry_t::is_defined)
  ;

  obj
    .def_prop_ro("key", &ResourceStringTable::key_u8,
      R"doc(
      An 8-digit hexadecimal number stored as a Unicode string. The four most
      significant digits represent the language identifier. The four least
      significant digits represent the code page for which the data is formatted.
      Each Microsoft Standard Language identifier contains two parts:
      the low-order 10 bits specify the major language, and the high-order 6
      bits specify the sublanguage.
      )doc"_doc
    )
    .def_prop_ro("type", nb::overload_cast<>(&ResourceStringTable::type, nb::const_),
      R"doc(
      The type of data in the version resource:
        * ``1`` if it contains text data
        * ``0`` if it contains binary data
      )doc"_doc
    )
    .def_prop_ro("entries", nb::overload_cast<>(&ResourceStringTable::entries),
      R"doc(Iterator over the different :class:`~.entry_t` in this table)doc"_doc
    )

    .def("get", nb::overload_cast<const std::string&>(&ResourceStringTable::get, nb::const_),
         "key"_a)

    .def("__getitem__", nb::overload_cast<const std::string&>(&ResourceStringTable::get, nb::const_),
         "key")
  ;
}
}
