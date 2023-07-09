/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include "ELF/pyELF.hpp"
#include "pyIterator.hpp"

#include <nanobind/operators.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/set.h>

#include "LIEF/Abstract/Section.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"

#include <string>
#include <sstream>

namespace LIEF::ELF::py {

template<>
void create<Section>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Section, LIEF::Section> sec(m, "Section",
      R"delim(
      Class which represents an ELF section.
      )delim"_doc);

  init_ref_iterator<Section::it_segments>(sec, "it_segments");

  sec
    .def(nb::init<>(),
        "Default constructor"_doc)

    .def("as_frame",
        &Section::as_frame,
        nb::rv_policy::reference_internal)

    .def_prop_ro("is_frame",
        &Section::is_frame)

    .def(nb::init<const std::string&, ELF_SECTION_TYPES>(),
        "Constructor from a name and a section type"_doc,
        "name"_a, "type"_a = ELF_SECTION_TYPES::SHT_PROGBITS)

    //.def(nb::init([] (Section& section, std::vector<uint8_t>& content, ELF_CLASS type) {
    //      return new Section(content.data(), type);
    //    }))

    .def_prop_rw("type",
        nb::overload_cast<>(&Section::type, nb::const_),
        nb::overload_cast<ELF_SECTION_TYPES>(&Section::type),
        "Return the " RST_CLASS_REF(lief.ELF.SECTION_TYPES) ""_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&Section::flags, nb::const_),
        nb::overload_cast<uint64_t>(&Section::flags),
        "Return the section's flags as an integer"_doc)

    .def_prop_ro("flags_list",
        &Section::flags_list,
        "Return section's flags as a list of " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) ""_doc)

    .def_prop_rw("file_offset",
        nb::overload_cast<>(&Section::file_offset, nb::const_),
        nb::overload_cast<uint64_t>(&Section::file_offset),
        "Offset of the section's content"_doc)

    .def_prop_ro("original_size",
        &Section::original_size,
        R"delim(
        Original size of the section's data.

        This value is used by the :class:`~lief.ELF.Builder` to determine if it needs
        to be relocated to avoid an override of the data
        )delim"_doc)

    .def_prop_rw("alignment",
        nb::overload_cast<>(&Section::alignment, nb::const_),
        nb::overload_cast<uint64_t>(&Section::alignment),
        "Section alignment"_doc)

    .def_prop_rw("information",
        nb::overload_cast<>(&Section::information, nb::const_),
        nb::overload_cast<uint32_t>(&Section::information),
        "Section information (this value depends on the section)"_doc)

    .def_prop_rw("entry_size",
        nb::overload_cast<>(&Section::entry_size, nb::const_),
        nb::overload_cast<uint64_t>(&Section::entry_size),
        R"delim(
        This property returns the size of an element in the case of a section that
        contains an array.

        :Example:

            The `.dynamic` section contains an array of :class:`~lief.ELF.DynamicEntry`. As the
            size of the raw C structure of this entry is 0x10 (``sizeof(Elf64_Dyn)``)
            in a ELF64, the :attr:`~lief.ELF.Section.entry_size`,
            is set to this value.
        )delim"_doc)

    .def_prop_rw("link",
        nb::overload_cast<>(&Section::link, nb::const_),
        nb::overload_cast<uint32_t>(&Section::link),
        "Index to another section"_doc)

    .def_prop_ro("segments",
      nb::overload_cast<>(&Section::segments),
      "Return segment(s) associated with the given section"_doc,
      nb::keep_alive<0, 1>())

    .def("clear", &Section::clear,
      "Clear the content of the section with the given ``value``"_doc,
      "value"_a = 0,
      nb::rv_policy::reference_internal)

    .def("add",
        &Section::add,
        "Add the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " to the list of "
        ":attr:`~lief.ELF.Section.flags`"_doc,
        "flag"_a)

    .def("remove",
        &Section::remove,
        "Remove the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " from the list of "
        ":attr:`~lief.ELF.Section.flags`"_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<ELF_SECTION_FLAGS>(&Section::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " is present"_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<const Segment&>(&Section::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.Segment) " is present "
        "in :attr:`~lief.ELF.Section.segments`"_doc,
        "segment"_a)

    .def(nb::self += ELF_SECTION_FLAGS())
    .def(nb::self -= ELF_SECTION_FLAGS())

    .def("__contains__",
        nb::overload_cast<ELF_SECTION_FLAGS>(&Section::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.SECTION_FLAGS) " is present"_doc)


    .def("__contains__",
        nb::overload_cast<const Segment&>(&Section::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.Segment) " is present "
        "in :attr:`~lief.ELF.Section.segments`"_doc)

    LIEF_DEFAULT_STR(LIEF::ELF::Section);
}


}
