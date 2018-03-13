/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/Import.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Import::*)(void) const;

template<class T>
using setter_t = void (Import::*)(T);

template<class T>
using no_const_getter = T (Import::*)(void);

template<class T, class P>
using no_const_func = T (Import::*)(P);

void init_PE_Import_class(py::module& m) {
  py::class_<Import, LIEF::Object>(m, "Import")
    .def(py::init<>(),
        "Default constructor with a library name")

    .def(py::init<const std::string&>(),
        "Constructor with a library name",
        "library_name"_a)

    .def_property_readonly("entries",
        static_cast<no_const_getter<it_import_entries>>(&Import::entries),
        "Iterator to the imported " RST_CLASS_REF(lief.PE.ImportEntry) " (functions)",
        py::return_value_policy::reference)

    .def_property("name",
        [] (const Import& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&Import::name),
        "Library name (e.g. ``kernel32.dll``)",
        py::return_value_policy::reference)

    .def_property_readonly("directory",
        static_cast<no_const_getter<DataDirectory&>>(&Import::directory),
        "" RST_CLASS_REF(lief.PE.DataDirectory) " associated with the import table",
        py::return_value_policy::reference)

    .def_property_readonly("iat_directory",
        static_cast<no_const_getter<DataDirectory&>>(&Import::iat_directory),
        "" RST_CLASS_REF(lief.PE.DataDirectory) " associated with the ``IAT`` table",
        py::return_value_policy::reference)

    .def_property("import_address_table_rva",
        static_cast<getter_t<uint32_t>>(&Import::import_address_table_rva),
        static_cast<setter_t<uint32_t>>(&Import::import_address_table_rva),
        "The RVA of the import address table. The contents of "
        "this table are **identical** to the contents of the import "
        "lookup table until the image is bound.")

    .def_property("import_lookup_table_rva",
        static_cast<getter_t<uint32_t>>(&Import::import_lookup_table_rva),
        static_cast<setter_t<uint32_t>>(&Import::import_lookup_table_rva),
        "The RVA of the import lookup table. This table "
        "contains a :attr:`~lief.PE.ImportEntry.name` or :attr:`~lief.PE.ImportEntry.ordinal` for each import.")

    .def("get_function_rva_from_iat",
        &Import::get_function_rva_from_iat,
        "Return the relative virtual address of the given function within the *Import Address Table*"
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
      static_cast<no_const_func<ImportEntry&, const std::string&>>(&Import::get_entry),
      "Return " RST_CLASS_REF(lief.PE.ImportEntry) " with the given name",
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
