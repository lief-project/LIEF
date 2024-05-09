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
#include "PE/pyPE.hpp"
#include "pySafeString.hpp"

#include "LIEF/PE/ExportEntry.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<ExportEntry>(nb::module_& m) {
  nb::class_<ExportEntry, LIEF::Symbol> export_entry(m, "ExportEntry",
      R"delim(
      Class which represents a PE Export entry (cf. :class:`lief.PE.Export`)
      )delim"_doc);

  nb::class_<ExportEntry::forward_information_t>(export_entry, "forward_information_t")
    .def_rw("library", &ExportEntry::forward_information_t::library)
    .def_rw("function", &ExportEntry::forward_information_t::function)
    LIEF_DEFAULT_STR(ExportEntry::forward_information_t);

  export_entry
    .def(nb::init<>())

    .def_prop_rw("name",
        [] (const ExportEntry& obj) {
          return LIEF::py::safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&ExportEntry::name))

    .def_prop_rw("ordinal",
        nb::overload_cast<>(&ExportEntry::ordinal, nb::const_),
        nb::overload_cast<uint16_t>(&ExportEntry::ordinal))

    .def_prop_rw("address",
        nb::overload_cast<>(&ExportEntry::address, nb::const_),
        nb::overload_cast<uint32_t>(&ExportEntry::address))

    .def_prop_rw("is_extern",
        nb::overload_cast<>(&ExportEntry::is_extern, nb::const_),
        nb::overload_cast<bool>(&ExportEntry::is_extern))

    .def_prop_ro("is_forwarded",
        &ExportEntry::is_forwarded)

    .def_prop_ro("forward_information",
        &ExportEntry::forward_information)

    .def_prop_ro("function_rva",
        &ExportEntry::function_rva)

    LIEF_DEFAULT_STR(ExportEntry);

}
}
