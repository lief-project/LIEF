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
#include "LIEF/PE/ExportEntry.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (ExportEntry::*)(void) const;

template<class T>
using setter_t = void (ExportEntry::*)(T);

void init_PE_ExportEntry_class(py::module& m) {
  py::class_<ExportEntry, LIEF::Object>(m, "ExportEntry")
    .def(py::init<>())

    .def_property("name",
        [] (const ExportEntry& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&ExportEntry::name))

    .def_property("ordinal",
        static_cast<getter_t<uint16_t>>(&ExportEntry::ordinal),
        static_cast<setter_t<uint16_t>>(&ExportEntry::ordinal))

    .def_property("address",
        static_cast<getter_t<uint32_t>>(&ExportEntry::address),
        static_cast<setter_t<uint32_t>>(&ExportEntry::address))

    .def_property("is_extern",
        static_cast<getter_t<bool>>(&ExportEntry::is_extern),
        static_cast<setter_t<bool>>(&ExportEntry::is_extern))

    .def("__eq__", &ExportEntry::operator==)
    .def("__ne__", &ExportEntry::operator!=)
    .def("__hash__",
        [] (const ExportEntry& export_entry) {
          return Hash::hash(export_entry);
        })

    .def("__str__", [] (const ExportEntry& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str = stream.str();
          return str;
        });


}
