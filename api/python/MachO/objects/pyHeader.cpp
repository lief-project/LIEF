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
#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/Header.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);


template<>
void create<Header>(py::module& m) {

  py::class_<Header, LIEF::Object>(m, "Header",
      "Class that represents the Mach-O header")
    .def(py::init<>())

    .def_property("magic",
        static_cast<getter_t<MACHO_TYPES>>(&Header::magic),
        static_cast<setter_t<MACHO_TYPES>>(&Header::magic),
        R"delim(
        The Mach-O magic bytes. These bytes determine whether it is
        a 32 bits Mach-O, a 64 bits Mach-O files etc.
        )delim")

    .def_property("cpu_type",
        static_cast<getter_t<CPU_TYPES>>(&Header::cpu_type),
        static_cast<setter_t<CPU_TYPES>>(&Header::cpu_type),
        "Target CPU ( " RST_CLASS_REF(lief.MachO.CPU_TYPES) ")")

    .def_property("cpu_subtype",
        static_cast<getter_t<uint32_t>>(&Header::cpu_subtype),
        static_cast<setter_t<uint32_t>>(&Header::cpu_subtype),
        R"delim(
        Return the CPU subtype supported by the Mach-O binary.
        For ARM architectures, this value could represent the minimum version
        for which the Mach-O binary has been compiled for.
        )delim")

    .def_property("file_type",
        static_cast<getter_t<FILE_TYPES>>(&Header::file_type),
        static_cast<setter_t<FILE_TYPES>>(&Header::file_type),
        "Binary's type ( " RST_CLASS_REF(lief.MachO.FILE_TYPES) ")")

    .def_property("flags",
        static_cast<getter_t<uint32_t>>(&Header::flags),
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
        "According to the official documentation, a reserved value")

    .def_property_readonly("flags_list",
        &Header::flags_list,
        "" RST_CLASS_REF(lief.PE.HEADER_FLAGS) " as a list")

    .def("add",
        static_cast<void (Header::*)(HEADER_FLAGS)>(&Header::add),
        "Add the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) "",
        "flag"_a)

    .def("remove",
        static_cast<void (Header::*)(HEADER_FLAGS)>(&Header::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) "",
        "flag"_a)

    .def("has",
        static_cast<bool (Header::*)(HEADER_FLAGS) const>(&Header::has),
        "``True`` if the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) " is in the "
        ":attr:`~lief.MachO.Header.flags`",
        "flag"_a)


    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })

    .def(py::self += HEADER_FLAGS())
    .def(py::self -= HEADER_FLAGS())

    .def("__contains__",
        static_cast<bool (Header::*)(HEADER_FLAGS) const>(&Header::has),
        "Check if the given " RST_CLASS_REF(lief.MachO.HEADER_FLAGS) " is present")


    .def("__str__",
        [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}

}
}
