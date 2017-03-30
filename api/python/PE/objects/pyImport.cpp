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

#include "LIEF/visitors/Hash.hpp"
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
  py::class_<Import>(m, "Import")
    .def(py::init<>())
    .def(py::init<const std::string&>())

    .def_property_readonly("entries",
        static_cast<no_const_getter<it_import_entries>>(&Import::entries),
        py::return_value_policy::reference)

    .def_property_readonly("name",
        static_cast<no_const_getter<std::string&>>(&Import::name),
        py::return_value_policy::reference)

    .def_property_readonly("directory",
        static_cast<no_const_getter<DataDirectory&>>(&Import::directory),
        py::return_value_policy::reference)

    .def_property_readonly("iat_directory",
        static_cast<no_const_getter<DataDirectory&>>(&Import::iat_directory),
        py::return_value_policy::reference)

    .def_property("import_address_table_rva",
        static_cast<getter_t<uint32_t>>(&Import::import_address_table_rva),
        static_cast<setter_t<uint32_t>>(&Import::import_address_table_rva))

    .def_property("import_lookup_table_rva",
        static_cast<getter_t<uint32_t>>(&Import::import_lookup_table_rva),
        static_cast<setter_t<uint32_t>>(&Import::import_lookup_table_rva))

    .def("get_function_rva_from_iat",
        &Import::get_function_rva_from_iat)

    .def("add_entry",
        static_cast<ImportEntry& (Import::*)(const ImportEntry&)>(&Import::add_entry),
        py::return_value_policy::reference)

    .def("add_entry",
        static_cast<ImportEntry& (Import::*)(const std::string&)>(&Import::add_entry),
        py::return_value_policy::reference)

    .def("get_entry",
      static_cast<no_const_func<ImportEntry&, const std::string&>>(&Import::get_entry),
      "Check return " RST_CLASS_REF(lief.PE.ImportEntry) " with the given name",
      py::return_value_policy::reference)


    .def("__eq__", &Import::operator==)
    .def("__ne__", &Import::operator!=)
    .def("__hash__",
        [] (const Import& import) {
          return LIEF::Hash::hash(import);
        })


    .def("__str__", [] (const Import& import)
        {
          std::ostringstream stream;
          stream << import;
          std::string str = stream.str();
          return str;
        });


}
