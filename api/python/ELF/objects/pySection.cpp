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
#include "pyELF.hpp"
#include "pyIterators.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (Section::*)(void) const;

template<class T>
using setter_t = void (Section::*)(T);

template<class T>
using no_const_getter = T (Section::*)(void);


template<>
void create<Section>(py::module& m) {

  // Section object
  py::class_<Section, LIEF::Section> sec(m, "Section",
      R"delim(
      Class which represents an ELF section.
      )delim");

  init_ref_iterator<Section::it_segments>(sec, "it_segments");

  sec
    .def(py::init<>(),
        "Default constructor")

    .def("as_frame",
        &Section::as_frame,
        py::return_value_policy::reference_internal)

    .def_property_readonly("is_frame",
        &Section::is_frame)

    .def(py::init<const std::string&, ELF_SECTION_TYPES>(),
        "Constructor from a name and a section type",
        "name"_a, "type"_a = ELF_SECTION_TYPES::SHT_PROGBITS)

    .def(py::init([] (Section& section, std::vector<uint8_t>& content, ELF_CLASS type) {
          return new Section(content.data(), type);
        }))

    .def_property("type",
        static_cast<getter_t<ELF_SECTION_TYPES>>(&Section::type),
        static_cast<setter_t<ELF_SECTION_TYPES>>(&Section::type),
        "Return the " RST_CLASS_REF(lief.ELF.SECTION_TYPES) "")

    .def_property("flags",
        static_cast<getter_t<uint64_t>>(&Section::flags),
        static_cast<setter_t<uint64_t>>(&Section::flags),
        "Return the section's flags as an integer")

    .def_property_readonly("flags_list",
        &Section::flags_list,
        "Return section's flags as a list of " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) "")

    .def_property("file_offset",
        static_cast<getter_t<uint64_t>>(&Section::file_offset),
        static_cast<setter_t<uint64_t>>(&Section::file_offset),
        "Offset of the section's content")

    .def_property_readonly("original_size",
        static_cast<getter_t<uint64_t>>(&Section::original_size),
        R"delim(
        Original size of the section's data.

        This value is used by the :class:`~lief.ELF.Builder` to determine if it needs
        to be relocated to avoid an override of the data
        )delim")

    .def_property("alignment",
        static_cast<getter_t<uint64_t>>(&Section::alignment),
        static_cast<setter_t<uint64_t>>(&Section::alignment),
        "Section alignment")

    .def_property("information",
        static_cast<getter_t<uint64_t>>(&Section::information),
        static_cast<setter_t<uint32_t>>(&Section::information),
        "Section information (this value depends on the section)")

    .def_property("entry_size",
        static_cast<getter_t<uint64_t>>(&Section::entry_size),
        static_cast<setter_t<uint64_t>>(&Section::entry_size),
        R"delim(
        This property returns the size of an element in the case of a section that
        contains an array.

        :Example:

            The `.dynamic` section contains an array of :class:`~lief.ELF.DynamicEntry`. As the
            size of the raw C structure of this entry is 0x10 (``sizeof(Elf64_Dyn)``)
            in a ELF64, the :attr:`~lief.ELF.Section.entry_size`,
            is set to this value.
        )delim")

    .def_property("link",
        static_cast<getter_t<uint32_t>>(&Section::link),
        static_cast<setter_t<uint32_t>>(&Section::link),
        "Index to another section")

    .def_property_readonly("segments",
      static_cast<no_const_getter<Section::it_segments>>(&Section::segments),
      "Return segment(s) associated with the given section",
      py::return_value_policy::reference_internal)

    .def("clear",
      &Section::clear,
      "Clear the content of the section with the given ``value``",
      "value"_a = 0,
      py::return_value_policy::reference)

    .def("add",
        &Section::add,
        "Add the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " to the list of "
        ":attr:`~lief.ELF.Section.flags`",
        "flag"_a)

    .def("remove",
        &Section::remove,
        "Remove the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " from the list of "
        ":attr:`~lief.ELF.Section.flags`",
        "flag"_a)

    .def("has",
        static_cast<bool (Section::*)(ELF_SECTION_FLAGS) const>(&Section::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " is present",
        "flag"_a)

    .def("has",
        static_cast<bool (Section::*)(const Segment&) const>(&Section::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.Segment) " is present "
        "in :attr:`~lief.ELF.Section.segments`",
        "segment"_a)

    .def("__eq__", &Section::operator==)
    .def("__ne__", &Section::operator!=)
    .def("__hash__",
        [] (const Section& section) {
          return Hash::hash(section);
        })

    .def(py::self += ELF_SECTION_FLAGS())
    .def(py::self -= ELF_SECTION_FLAGS())

    .def("__contains__",
        static_cast<bool (Section::*)(ELF_SECTION_FLAGS) const>(&Section::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " is present")


    .def("__contains__",
        static_cast<bool (Section::*)(const Segment&) const>(&Section::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.Segment) " is present "
        "in :attr:`~lief.ELF.Section.segments`")

    .def("__str__",
        [] (const Section& section)
        {
          std::ostringstream stream;
          stream << section;
          return stream.str();
        });
}


}
}
