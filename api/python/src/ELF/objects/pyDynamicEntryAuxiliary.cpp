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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "ELF/pyELF.hpp"
#include "pySafeString.hpp"

#include "LIEF/ELF/DynamicEntryAuxiliary.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF::ELF::py {

template<>
void create<DynamicEntryAuxiliary>(nb::module_& m) {
  nb::class_<DynamicEntryAuxiliary, DynamicEntry>(m, "DynamicEntryAuxiliary",
      R"doc(
      Class which represents a ``DT_AUXILIARY`` entry in the dynamic table.
      This kind of entry is used to specify a shared object that should be
      loaded before the current one.
      )doc"_doc)

    .def(nb::init<const std::string &>(),
        "Constructor from library name"_doc,
        "library_name"_a)

    .def_prop_rw("name",
        [] (const DynamicEntryAuxiliary& obj) {
          return LIEF::py::safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&DynamicEntryAuxiliary::name),
        "Return the library name"_doc)

    LIEF_DEFAULT_STR(DynamicEntryAuxiliary);
}

}
