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
#include <string>
#include <sstream>

#include <nanobind/operators.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryArray>(nb::module_& m) {
  nb::class_<DynamicEntryArray, DynamicEntry>(m, "DynamicEntryArray",
      R"delim(
      Class that represent an Array in the dynamic table.
      This entry is associated with constructors:
      - ``DT_PREINIT_ARRAY``
      - ``DT_INIT_ARRAY``
      - ``DT_FINI_ARRAY``

      The underlying values are 64-bits integers to cover both:
      ELF32 and ELF64 binaries.
      )delim"_doc)

    .def(nb::init<DynamicEntry::TAG, DynamicEntryArray::array_t>(),
        "tag"_a, "array"_a)

    .def_prop_rw("array",
        nb::overload_cast<>(&DynamicEntryArray::array, nb::const_),
        nb::overload_cast<const std::vector<uint64_t>&>(&DynamicEntryArray::array),
        "Return the array as a list of intergers"_doc,
        nb::rv_policy::reference_internal)

    .def("insert",
        &DynamicEntryArray::insert,
        "Insert the given ``function`` at ``pos``"_doc,
        "pos"_a, "function"_a,
        nb::rv_policy::reference_internal)

    .def("append",
        &DynamicEntryArray::append,
        "Append the given ``function`` "_doc,
        "function"_a,
        nb::rv_policy::reference_internal)

    .def("remove",
        &DynamicEntryArray::remove,
        "Remove the given ``function`` "_doc,
        "function"_a,
        nb::rv_policy::reference_internal)

    .def(nb::self += uint64_t())
    .def(nb::self -= uint64_t())

    .def("__getitem__",
        nb::overload_cast<size_t>(&DynamicEntryArray::operator[]),
        nb::rv_policy::reference_internal)

    .def("__len__",
        &DynamicEntryArray::size)

    LIEF_DEFAULT_STR(DynamicEntryArray);
}

}
