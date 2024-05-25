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
#include "pyIterator.hpp"
#include "pyErr.hpp"
#include "pySafeString.hpp"

#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/DataDirectory.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<Import>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Import, LIEF::Object> imp(m, "Import",
      R"delim(
      Class that represents a PE import
      )delim"_doc);

  init_ref_iterator<Import::it_entries>(imp, "it_entries");

  imp
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def(nb::init<const std::string&>(),
        "Constructor from a library name"_doc,
        "library_name"_a)

    .def_prop_ro("forwarder_chain",
        &Import::forwarder_chain,
        "The index of the first forwarder reference"_doc)

    .def_prop_ro("timedatestamp",
        &Import::timedatestamp,
        R"delim(
        The stamp that is set to zero until the image is bound.

        After the image is bound, this field is set to the time/data stamp of the DLL
        )delim"_doc)

    .def_prop_ro("entries",
        nb::overload_cast<>(&Import::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.ImportEntry) " (functions)"_doc,
        nb::keep_alive<1, 0>())

    .def_prop_rw("name",
        [] (const Import& obj) {
          return safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&Import::name),
        "Library name (e.g. ``kernel32.dll``)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("directory",
        nb::overload_cast<>(&Import::directory),
        R"delim(
        Return the :class:`~lief.PE.DataDirectory` associated with this import.

        It should be the one at index :attr:`lief.PE.DataDirectory.TYPES.IMPORT_TABLE`.
        It can return None if the Import directory can't be resolved.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("iat_directory",
        nb::overload_cast<>(&Import::iat_directory),
        R"delim(
        Return the :class:`~lief.PE.DataDirectory` associated with the ``IAT`` table.

        It should be the one at index :attr:`lief.PE.DataDirectory.TYPES.IAT`. It can
        return None if the IAT directory can't be resolved.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("import_address_table_rva",
        nb::overload_cast<>(&Import::import_address_table_rva, nb::const_),
        nb::overload_cast<uint32_t>(&Import::import_address_table_rva),
        R"delim(
        The RVA of the import address table (``IAT``). The content of this
        table is **identical** to the content of the Import Lookup Table (``ILT``)
        until the image is bound.

        .. warning::

            This address could change when re-building the binary
        )delim"_doc)

    .def_prop_rw("import_lookup_table_rva",
        nb::overload_cast<>(&Import::import_lookup_table_rva, nb::const_),
        nb::overload_cast<uint32_t>(&Import::import_lookup_table_rva),
        R"delim(
        The RVA of the import lookup table. This table
        contains the :attr:`~lief.PE.ImportEntry.name` or the :attr:`~lief.PE.ImportEntry.ordinal`
        for all the imports.
        )delim"_doc)

    .def("get_function_rva_from_iat",
        [] (const Import& self, const std::string& name) {
          return error_or(&Import::get_function_rva_from_iat, self, name);
        },
        "Return the relative virtual address of the given function within the *Import Address Table*"_doc,
        "function_name"_a)

    .def("add_entry",
        nb::overload_cast<ImportEntry>(&Import::add_entry),
        "Add an " RST_CLASS_REF(lief.PE.ImportEntry) " (function) to the current import"_doc,
        "entry"_a,
        nb::rv_policy::reference_internal)

    .def("add_entry",
        nb::overload_cast<const std::string&>(&Import::add_entry),
        "Add an " RST_CLASS_REF(lief.PE.ImportEntry) " (function) to the current import"_doc,
        "function_name"_a,
        nb::rv_policy::reference_internal)

    .def("get_entry",
      nb::overload_cast<const std::string&>(&Import::get_entry),
      "Return the " RST_CLASS_REF(lief.PE.ImportEntry) " with the given name or None if not found"_doc,
      "function_name"_a,
      nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(Import);

}
}
