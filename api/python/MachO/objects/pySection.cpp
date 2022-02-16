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
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"

#include "pyMachO.hpp"
#include "pyIterators.hpp"

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

  py::class_<Section, LIEF::Section> sec(m, "Section",
      "Class that represents a Mach-O section");
  try {
    /*
     * it_relocations could be already registered by the SegmentCommand
     */
    init_ref_iterator<Section::it_relocations>(sec, "it_relocations");
  } catch (const std::runtime_error&) { }

  sec
    .def(py::init<>())

    .def(py::init<const std::string&>(),
        "Constructor from a section's name",
        "section_name"_a)

    .def(py::init<const std::string&, const Section::content_t&>(),
        "Constructor from a section's name and its content",
        "section_name"_a, "content"_a)

    .def_property("alignment",
        static_cast<getter_t<uint32_t>>(&Section::alignment),
        static_cast<setter_t<uint32_t>>(&Section::alignment),
        "Section's alignment as a power of 2")

    .def_property("relocation_offset",
        static_cast<getter_t<uint32_t>>(&Section::relocation_offset),
        static_cast<setter_t<uint32_t>>(&Section::relocation_offset),
        R"delim(
        Offset of the relocation table. This value should be 0
        for executable and libraries as the relocations are managed by the :attr:`lief.MachO.DyldInfo.rebase`

        Other the other hand, for object files (``.o``) this value should not be 0
        )delim")

    .def_property("numberof_relocations",
        static_cast<getter_t<uint32_t>>(&Section::numberof_relocations),
        static_cast<setter_t<uint32_t>>(&Section::numberof_relocations),
        "Number of relocations associated with this section")

    .def_property("type",
        static_cast<getter_t<MACHO_SECTION_TYPES>>(&Section::type),
        static_cast<setter_t<MACHO_SECTION_TYPES>>(&Section::type),
        R"delim(
        Type of the section. This value can help to determine
        the purpose of the section (c.f. :class:`~lief.MachO.MACHO_SECTION_TYPES`)
        )delim")

    .def_property_readonly("relocations",
        static_cast<no_const_getter<Section::it_relocations>>(&Section::relocations),
        "Iterator over the " RST_CLASS_REF(lief.MachO.Relocation) " (if any)",
        py::return_value_policy::reference_internal)

    .def_property("reserved1",
        static_cast<getter_t<uint32_t>>(&Section::reserved1),
        static_cast<setter_t<uint32_t>>(&Section::reserved1),
        "According to the official ``loader.h`` file, this value is reserved for *offset* or *index*")

    .def_property("reserved2",
        static_cast<getter_t<uint32_t>>(&Section::reserved2),
        static_cast<setter_t<uint32_t>>(&Section::reserved2),
        "According to the official ``loader.h`` file, this value is reserved for *offset* or *index*")

    .def_property("reserved3",
        static_cast<getter_t<uint32_t>>(&Section::reserved3),
        static_cast<setter_t<uint32_t>>(&Section::reserved3),
        "According to the official ``loader.h`` file, this value is reserved for *offset* or *index*")

    .def_property("flags",
        static_cast<getter_t<uint32_t>>(&Section::flags),
        static_cast<setter_t<uint32_t>>(&Section::flags),
        "Section's flags masked with SECTION_FLAGS_MASK (see: :class:`~lief.MachO.MACHO_SECTION_FLAGS`)")

    .def_property_readonly("flags_list",
        static_cast<getter_t<Section::flag_list_t>>(&Section::flags_list),
        py::return_value_policy::reference_internal)

    .def_property_readonly("segment",
        static_cast<SegmentCommand* (Section::*)(void)>(&Section::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with the section or None if not present",
        py::return_value_policy::reference)

    .def_property("segment_name",
        static_cast<getter_t<const std::string&>>(&Section::segment_name),
        static_cast<setter_t<const std::string&>>(&Section::segment_name),
        R"delim(
        The segment name associated with the section
        )delim")

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

