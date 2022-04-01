/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyPE.hpp"
#include "pyIterators.hpp"
#include "pyErr.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/Import.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Import::*)(void) const;

template<class T>
using setter_t = void (Import::*)(T);

template<class T>
using no_const_getter = T (Import::*)(void);

template<class T, class P>
using no_const_func = T (Import::*)(P);


template<>
void create<Import>(py::module& m) {
  py::class_<Import, LIEF::Object> imp(m, "Import",
      R"delim(
      Class that represents a PE import
      )delim");

  init_ref_iterator<Import::it_entries>(imp, "it_entries");

  imp
    .def(py::init<>(),
        "Default constructor")

    .def(py::init<const std::string&>(),
        "Constructor from a library name",
        "library_name"_a)

    .def_property_readonly("forwarder_chain",
        &Import::forwarder_chain,
        "The index of the first forwarder reference")

    .def_property_readonly("timedatestamp",
        &Import::timedatestamp,
        R"delim(
        The stamp that is set to zero until the image is bound.

        After the image is bound, this field is set to the time/data stamp of the DLL
        )delim")

    .def_property_readonly("entries",
        static_cast<no_const_getter<Import::it_entries>>(&Import::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.ImportEntry) " (functions)",
        py::return_value_policy::reference)

    .def_property("name",
        [] (const Import& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&Import::name),
        "Library name (e.g. ``kernel32.dll``)",
        py::return_value_policy::reference)

    .def_property_readonly("directory",
        static_cast<no_const_getter<DataDirectory*>>(&Import::directory),
        R"delim(
        Return the :class:`~lief.PE.DataDirectory` associated with this import.

        It should be the one at index :attr:`lief.PE.DATA_DIRECTORY.IMPORT_TABLE`.
        It can return None if the Import directory can't be resolved.
        )delim",
        py::return_value_policy::reference)

    .def_property_readonly("iat_directory",
        static_cast<no_const_getter<DataDirectory*>>(&Import::iat_directory),
        R"delim(
        Return the :class:`~lief.PE.DataDirectory` associated with the ``IAT`` table.

        It should be the one at index :attr:`lief.PE.DATA_DIRECTORY.IAT`. It can
        return None if the IAT directory can't be resolved.
        )delim",
        py::return_value_policy::reference)

    .def_property("import_address_table_rva",
        static_cast<getter_t<uint32_t>>(&Import::import_address_table_rva),
        static_cast<setter_t<uint32_t>>(&Import::import_address_table_rva),
        R"delim(
        The RVA of the import address table (``IAT``). The content of this
        table is **identical** to the content of the Import Lookup Table (``ILT``)
        until the image is bound.

        .. warning::

            This address could change when re-building the binary
        )delim")

    .def_property("import_lookup_table_rva",
        static_cast<getter_t<uint32_t>>(&Import::import_lookup_table_rva),
        static_cast<setter_t<uint32_t>>(&Import::import_lookup_table_rva),
        R"delim(
        The RVA of the import lookup table. This table
        contains the :attr:`~lief.PE.ImportEntry.name` or the :attr:`~lief.PE.ImportEntry.ordinal`
        for all the imports.
        )delim")

    .def("get_function_rva_from_iat",
        [] (const Import& self, const std::string& name) {
          return error_or(&Import::get_function_rva_from_iat, self, name);
        },
        "Return the relative virtual address of the given function within the *Import Address Table*",
        "function_name"_a)

    .def("add_entry",
        static_cast<ImportEntry& (Import::*)(const ImportEntry&)>(&Import::add_entry),
        "Add an " RST_CLASS_REF(lief.PE.ImportEntry) " (function) to the current import",
        "entry"_a,
        py::return_value_policy::reference)

    .def("add_entry",
        static_cast<ImportEntry& (Import::*)(const std::string&)>(&Import::add_entry),
        "Add an " RST_CLASS_REF(lief.PE.ImportEntry) " (function) to the current import",
        "function_name"_a,
        py::return_value_policy::reference)

    .def("get_entry",
      static_cast<no_const_func<ImportEntry*, const std::string&>>(&Import::get_entry),
      "Return the " RST_CLASS_REF(lief.PE.ImportEntry) " with the given name or None if not found",
      "function_name"_a,
      py::return_value_policy::reference)


    .def("__eq__", &Import::operator==)
    .def("__ne__", &Import::operator!=)
    .def("__hash__",
        [] (const Import& import) {
          return Hash::hash(import);
        })


    .def("__str__", [] (const Import& import)
        {
          std::ostringstream stream;
          stream << import;
          std::string str = stream.str();
          return str;
        });
}
}
}
