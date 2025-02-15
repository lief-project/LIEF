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
#include "pySafeString.hpp"

#include "LIEF/PE/Export.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<Export>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Export, LIEF::Object> exp(m, "Export",
      R"delim(
      Class which represents a PE Export
      )delim"_doc);

  init_ref_iterator<Export::it_entries>(exp, "it_entries");

  exp
    .def(nb::init<>(), "Default constructor"_doc)
    .def(nb::init<std::string, const Export::entries_t&>(),
         "name"_a, "entries"_a,
         "Constructor from DLL name and its exports"_doc)

    .def_prop_rw("name",
        [] (const Export& obj) {
          return safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&Export::name),
        "The name of the library exported (e.g. ``KERNEL32.dll``)"_doc)

    .def_prop_rw("export_flags",
        nb::overload_cast<>(&Export::export_flags, nb::const_),
        nb::overload_cast<uint32_t>(&Export::export_flags),
        "According to the PE specifications this value is reserved and should be set to 0"_doc)

    .def_prop_rw("timestamp",
        nb::overload_cast<>(&Export::timestamp, nb::const_),
        nb::overload_cast<uint32_t>(&Export::timestamp),
        "The time and date that the export data was created"_doc)

    .def_prop_rw("major_version",
        nb::overload_cast<>(&Export::major_version, nb::const_),
        nb::overload_cast<uint16_t>(&Export::major_version),
        "The major version number (can be user-defined)"_doc)

    .def_prop_rw("minor_version",
        nb::overload_cast<>(&Export::minor_version, nb::const_),
        nb::overload_cast<uint16_t>(&Export::minor_version),
        "The minor version number (can be user-defined)"_doc)

    .def_prop_rw("ordinal_base",
        nb::overload_cast<>(&Export::ordinal_base, nb::const_),
        nb::overload_cast<uint32_t>(&Export::ordinal_base),
        "The starting number for the exports. Usually this value is set to 1"_doc)

    .def_prop_ro("entries",
        nb::overload_cast<>(&Export::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.ExportEntry) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("name_rva", &Export::name_rva,
                 "Address of the ASCII DLL's name (RVA)"_doc)

    .def_prop_ro("export_addr_table_rva", &Export::export_addr_table_rva,
                 "RVA of the export address table"_doc)

    .def_prop_ro("export_addr_table_cnt", &Export::export_addr_table_cnt,
                 "Number of entries in the export address table"_doc)

    .def_prop_ro("names_addr_table_rva", &Export::names_addr_table_rva,
                 "RVA to the list of exported names"_doc)

    .def_prop_ro("names_addr_table_cnt", &Export::names_addr_table_cnt,
                 "Number of exports by name"_doc)

    .def_prop_ro("ord_addr_table_rva", &Export::ord_addr_table_rva,
                 "RVA to the list of exported ordinals"_doc)

    .def("find_entry", nb::overload_cast<const std::string&>(&Export::find_entry),
         "Find the export with the given name"_doc,
         "name"_a, nb::rv_policy::reference_internal)

    .def("find_entry", nb::overload_cast<uint32_t>(&Export::find_entry),
         "Find the export entry with the given ordinal number"_doc,
         "ordinal"_a, nb::rv_policy::reference_internal)

    .def("find_entry_at", nb::overload_cast<uint32_t>(&Export::find_entry_at),
         "Find the export entry at the provided RVA"_doc,
         "rva_addr"_a, nb::rv_policy::reference_internal)

    .def("add_entry", nb::overload_cast<const ExportEntry&>(&Export::add_entry),
         "Add the given export and return the newly created and added entry"_doc,
         "exp"_a, nb::rv_policy::reference_internal)

    .def("add_entry", nb::overload_cast<std::string, uint32_t>(&Export::add_entry),
         "Add the given export and return the newly created and added entry"_doc,
         "name"_a, "addr"_a, nb::rv_policy::reference_internal)

    .def("remove_entry", nb::overload_cast<const ExportEntry&>(&Export::remove_entry),
         "Remove the given export entry", "entry"_a)

    .def("remove_entry", nb::overload_cast<const std::string&>(&Export::remove_entry),
         "Remove the export entry with the given name", "name"_a)

    .def("remove_entry", nb::overload_cast<uint32_t>(&Export::remove_entry),
         "Remove the export entry with the given RVA", "rva"_a)

    LIEF_COPYABLE(Export)
    LIEF_DEFAULT_STR(Export);
}

}
