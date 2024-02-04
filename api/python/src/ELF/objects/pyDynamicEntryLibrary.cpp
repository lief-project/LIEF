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
#include <nanobind/stl/string.h>

#include "ELF/pyELF.hpp"
#include "pySafeString.hpp"

#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryLibrary>(nb::module_& m) {
  nb::class_<DynamicEntryLibrary, DynamicEntry>(m, "DynamicEntryLibrary",
      R"delim(
      Class which represents a ``DT_NEEDED`` entry in the dynamic table.

      This kind of entry is usually used to create library dependency.
      )delim"_doc)

    .def(nb::init<const std::string &>(),
        "Constructor from a library name"_doc,
        "library_name"_a)

    .def_prop_rw("name",
        [] (const DynamicEntryLibrary& obj) {
          return LIEF::py::safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&DynamicEntryLibrary::name),
        "Library associated with this entry (e.g. ``libc.so.6``)"_doc)

    LIEF_DEFAULT_STR(DynamicEntryLibrary);
}

}
