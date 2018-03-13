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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (ExportInfo::*)(void) const;

template<class T>
using setter_t = void (ExportInfo::*)(T);


void init_MachO_ExportInfo_class(py::module& m) {

  py::class_<ExportInfo, LIEF::Object>(m, "ExportInfo")

    .def_property_readonly("node_offset",
        static_cast<getter_t<uint64_t>>(&ExportInfo::node_offset))

    .def_property("flags",
        static_cast<getter_t<uint64_t>>(&ExportInfo::flags),
        static_cast<setter_t<uint64_t>>(&ExportInfo::flags),
        py::return_value_policy::reference_internal)

    .def_property("address",
        static_cast<getter_t<uint64_t>>(&ExportInfo::address),
        static_cast<setter_t<uint64_t>>(&ExportInfo::address),
        py::return_value_policy::reference_internal)

    .def_property_readonly("has_symbol",
        &ExportInfo::has_symbol,
        "``True`` if the export info has a " RST_CLASS_REF(lief.MachO.Symbol) " associated with")

    .def_property_readonly("symbol",
        static_cast<Symbol& (ExportInfo::*)(void)>(&ExportInfo::symbol),
        "" RST_CLASS_REF(lief.MachO.Symbol) " associated with the export (if any)",
        py::return_value_policy::reference)


    .def("__eq__", &ExportInfo::operator==)
    .def("__ne__", &ExportInfo::operator!=)
    .def("__hash__",
        [] (const ExportInfo& export_info) {
          return Hash::hash(export_info);
        })


    .def("__str__",
        [] (const ExportInfo& export_info)
        {
          std::ostringstream stream;
          stream << export_info;
          std::string str = stream.str();
          return str;
        });

}
