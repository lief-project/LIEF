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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/DelayImport.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (DelayImport::*)() const;

template<class T>
using setter_t = void (DelayImport::*)(T);

template<class T>
using no_const_getter = T (DelayImport::*)();

template<class T, class P>
using no_const_func = T (DelayImport::*)(P);


template<>
void create<DelayImport>(py::module& m) {
  py::class_<DelayImport, LIEF::Object> imp(m, "DelayImport",
      R"delim(
      Class that represents a PE delay import
      )delim");

  init_ref_iterator<DelayImport::it_entries>(imp, "it_entries");

  imp
    .def(py::init<const std::string&>(),
        "Constructor from a library name",
        "library_name"_a)

    .def_property_readonly("entries",
        static_cast<no_const_getter<DelayImport::it_entries>>(&DelayImport::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.DelayImportEntry) " (functions)",
        py::return_value_policy::reference)

    .def_property("name",
        [] (const DelayImport& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<std::string>>(&DelayImport::name),
        "Library name (e.g. ``kernel32.dll``)",
        py::return_value_policy::reference_internal)

    .def_property("attribute",
        static_cast<getter_t<uint32_t>>(&DelayImport::attribute),
        static_cast<setter_t<uint32_t>>(&DelayImport::attribute),
        R"delim(
        Reserved and **should** be zero according to the PE specifications
        )delim")

    .def_property("handle",
        static_cast<getter_t<uint32_t>>(&DelayImport::handle),
        static_cast<setter_t<uint32_t>>(&DelayImport::handle),
        R"delim(
        The RVA of the module handle (in the ``.data`` section)
        It is used for storage by the routine that is supplied to manage delay-loading.
        )delim")

    .def_property("iat",
        static_cast<getter_t<uint32_t>>(&DelayImport::iat),
        static_cast<setter_t<uint32_t>>(&DelayImport::iat),
        R"delim(
        RVA of the delay-load import address table.
        )delim")

    .def_property("names_table",
        static_cast<getter_t<uint32_t>>(&DelayImport::names_table),
        static_cast<setter_t<uint32_t>>(&DelayImport::names_table),
        R"delim(
        RVA of the delay-load import names table.
        The content of this table has the layout as the Import lookup table
        )delim")

    .def_property("biat",
        static_cast<getter_t<uint32_t>>(&DelayImport::biat),
        static_cast<setter_t<uint32_t>>(&DelayImport::biat),
        R"delim(
        RVA of the **bound** delay-load import address table or 0
        if the table does not exist.
        )delim")


    .def_property("uiat",
        static_cast<getter_t<uint32_t>>(&DelayImport::uiat),
        static_cast<setter_t<uint32_t>>(&DelayImport::uiat),
        R"delim(
        RVA of the **unload** delay-load import address table or 0
        if the table does not exist.

        According to the PE specifications, this table is an
        exact copy of the delay import address table that can be
        used to to restore the original IAT the case of unloading.
        )delim")

    .def_property("timestamp",
        static_cast<getter_t<uint32_t>>(&DelayImport::timestamp),
        static_cast<setter_t<uint32_t>>(&DelayImport::timestamp),
        R"delim(
        The timestamp of the DLL to which this image has been bound.
        )delim")

    .def("__eq__", &DelayImport::operator==)
    .def("__ne__", &DelayImport::operator!=)
    .def("__hash__",
        [] (const DelayImport& import) {
          return Hash::hash(import);
        })


    .def("__str__", [] (const DelayImport& import)
        {
          std::ostringstream stream;
          stream << import;
          std::string str = stream.str();
          return str;
        });
}
}
}
