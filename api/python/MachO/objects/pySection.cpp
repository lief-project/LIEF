/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include "LIEF/MachO/Section.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (Section::*)(void) const;

template<class T>
using setter_t = void (Section::*)(T);

template<class T>
using no_const_getter = T (Section::*)(void);


template<>
void create<Section>(py::module& m) {

  py::class_<Section, LIEF::Section>(m, "Section")
    .def(py::init<>())

    .def(py::init<const std::string&>(),
        "Constructor with the section name",
        "section_name"_a)

    .def(py::init<const std::string&, const Section::content_t&>(),
        "Constructor with the section name and its content",
        "section_name"_a, "content"_a)

    .def_property("alignment",
        static_cast<getter_t<uint32_t>>(&Section::alignment),
        static_cast<setter_t<uint32_t>>(&Section::alignment),
        "Section's alignment ")

    .def_property("relocation_offset",
        static_cast<getter_t<uint32_t>>(&Section::relocation_offset),
        static_cast<setter_t<uint32_t>>(&Section::relocation_offset),
        "")

    .def_property("numberof_relocations",
        static_cast<getter_t<uint32_t>>(&Section::numberof_relocations),
        static_cast<setter_t<uint32_t>>(&Section::numberof_relocations),
        "")

    .def_property("type",
        static_cast<getter_t<MACHO_SECTION_TYPES>>(&Section::type),
        static_cast<setter_t<MACHO_SECTION_TYPES>>(&Section::type),
        "")

    .def_property_readonly("relocations",
        static_cast<no_const_getter<it_relocations>>(&Section::relocations),
        "Iterator over " RST_CLASS_REF(lief.MachO.Relocation) " (if any)",
        py::return_value_policy::reference_internal)

    .def_property("reserved1",
        static_cast<getter_t<uint32_t>>(&Section::reserved1),
        static_cast<setter_t<uint32_t>>(&Section::reserved1),
        "")

    .def_property("reserved2",
        static_cast<getter_t<uint32_t>>(&Section::reserved2),
        static_cast<setter_t<uint32_t>>(&Section::reserved2),
        "")

    .def_property("reserved3",
        static_cast<getter_t<uint32_t>>(&Section::reserved3),
        static_cast<setter_t<uint32_t>>(&Section::reserved3),
        "")

    .def_property("flags",
        static_cast<getter_t<uint32_t>>(&Section::flags),
        static_cast<setter_t<uint32_t>>(&Section::flags),
        "")

    .def_property_readonly("flags_list",
        static_cast<getter_t<Section::flag_list_t>>(&Section::flags_list),
        py::return_value_policy::reference_internal)

    .def_property_readonly("segment",
        static_cast<SegmentCommand& (Section::*)(void)>(&Section::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " segment associated with the section",
        py::return_value_policy::reference)

    .def_property_readonly("has_segment",
        &Section::has_segment,
        "True if the current section has a segment associated with")

    .def("has",
        static_cast<bool(Section::*)(MACHO_SECTION_FLAGS) const>(&Section::has),
        "Check if the section has the given " RST_CLASS_REF(lief.MachO.SECTION_FLAGS) "",
        "flag"_a)

    .def("add",
        static_cast<void(Section::*)(MACHO_SECTION_FLAGS)>(&Section::add),
        "Add the given " RST_CLASS_REF(lief.MachO.SECTION_FLAGS) "",
        "flag"_a)

    .def("remove",
        static_cast<void(Section::*)(MACHO_SECTION_FLAGS)>(&Section::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.SECTION_FLAGS) "",
        "flag"_a)

    .def(py::self += MACHO_SECTION_FLAGS())
    .def(py::self -= MACHO_SECTION_FLAGS())

    .def("__contains__",
        static_cast<bool (Section::*)(MACHO_SECTION_FLAGS) const>(&Section::has),
        "Check if the given " RST_CLASS_REF(lief.MachO.MACHO_SECTION_FLAGS) " is present")



    .def("__eq__", &Section::operator==)
    .def("__ne__", &Section::operator!=)
    .def("__hash__",
        [] (const Section& section) {
          return Hash::hash(section);
        })


    .def("__str__",
        [] (const Section& section)
        {
          std::ostringstream stream;
          stream << section;
          std::string str =  stream.str();
          return str;
        });

}

}
}

