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
#include <string>
#include <sstream>

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/MachO/Header.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

void init_MachO_Header_class(py::module& m) {

  py::class_<Header>(m, "Header")
    .def(py::init<>())

    .def_property("magic",
        static_cast<getter_t<uint32_t>>(&Header::magic),
        static_cast<setter_t<uint32_t>>(&Header::magic),
        ""
        )

    .def_property("cpu_type",
        static_cast<getter_t<CPU_TYPES>>(&Header::cpu_type),
        static_cast<setter_t<CPU_TYPES>>(&Header::cpu_type),
        "Target CPU ( " RST_CLASS_REF(lief.MachO.CPU_TYPES) ")")

    .def_property("cpu_subtype",
        static_cast<getter_t<uint32_t>>(&Header::cpu_subtype),
        static_cast<setter_t<uint32_t>>(&Header::cpu_subtype),
        "CPU subtype")

    .def_property("file_type",
        static_cast<getter_t<FILE_TYPES>>(&Header::file_type),
        static_cast<setter_t<FILE_TYPES>>(&Header::file_type),
        "Binary's type ( " RST_CLASS_REF(lief.MachO.FILE_TYPES) ")")

    .def_property("flags",
        &Header::flags_list,
        static_cast<setter_t<uint32_t>>(&Header::flags),
        "Binary's flags ( " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) ")")

    .def_property("nb_cmds",
        static_cast<getter_t<uint32_t>>(&Header::nb_cmds),
        static_cast<setter_t<uint32_t>>(&Header::nb_cmds),
        "Number of " RST_CLASS_REF(lief.MachO.LoadCommand) "")

    .def_property("sizeof_cmds",
        static_cast<getter_t<uint32_t>>(&Header::sizeof_cmds),
        static_cast<setter_t<uint32_t>>(&Header::sizeof_cmds),
        "Size of all " RST_CLASS_REF(lief.MachO.LoadCommand) "")

    .def_property("reserved",
        static_cast<getter_t<uint32_t>>(&Header::reserved),
        static_cast<setter_t<uint32_t>>(&Header::reserved),
        "")


    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return LIEF::Hash::hash(header);
        })


    .def("__str__",
        [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}
