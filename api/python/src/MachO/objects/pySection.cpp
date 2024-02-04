/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/set.h>
#include <nanobind/operators.h>

#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"

#include "MachO/pyMachO.hpp"
#include "pyIterator.hpp"

namespace LIEF::MachO::py {

template<>
void create<Section>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Section, LIEF::Section> sec(m, "Section",
      "Class that represents a Mach-O section"_doc);
  try {
    /*
     * it_relocations could be already registered by the SegmentCommand
     */
    init_ref_iterator<Section::it_relocations>(sec, "it_relocations");
  } catch (const std::runtime_error&) { }

  sec
    .def(nb::init<>())

    .def(nb::init<const std::string&>(),
        "Constructor from a section's name"_doc,
        "section_name"_a)

    .def(nb::init<const std::string&, const Section::content_t&>(),
        "Constructor from a section's name and its content"_doc,
        "section_name"_a, "content"_a)

    .def_prop_rw("alignment",
        nb::overload_cast<>(&Section::alignment, nb::const_),
        nb::overload_cast<uint32_t>(&Section::alignment),
        "Section's alignment as a power of 2"_doc)

    .def_prop_rw("relocation_offset",
        nb::overload_cast<>(&Section::relocation_offset, nb::const_),
        nb::overload_cast<uint32_t>(&Section::relocation_offset),
        R"delim(
        Offset of the relocation table. This value should be 0
        for executable and libraries as the relocations are managed by the :attr:`lief.MachO.DyldInfo.rebase`

        Other the other hand, for object files (``.o``) this value should not be 0
        )delim"_doc)

    .def_prop_rw("numberof_relocations",
        nb::overload_cast<>(&Section::numberof_relocations, nb::const_),
        nb::overload_cast<uint32_t>(&Section::numberof_relocations),
        "Number of relocations associated with this section"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&Section::type, nb::const_),
        nb::overload_cast<MACHO_SECTION_TYPES>(&Section::type),
        R"delim(
        Type of the section. This value can help to determine
        the purpose of the section (c.f. :class:`~lief.MachO.MACHO_SECTION_TYPES`)
        )delim"_doc)

    .def_prop_ro("relocations",
        nb::overload_cast<>(&Section::relocations),
        "Iterator over the " RST_CLASS_REF(lief.MachO.Relocation) " (if any)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_rw("reserved1",
        nb::overload_cast<>(&Section::reserved1, nb::const_),
        nb::overload_cast<uint32_t>(&Section::reserved1),
        "According to the official ``loader.h`` file, this value is reserved for *offset* or *index*"_doc)

    .def_prop_rw("reserved2",
        nb::overload_cast<>(&Section::reserved2, nb::const_),
        nb::overload_cast<uint32_t>(&Section::reserved2),
        "According to the official ``loader.h`` file, this value is reserved for *offset* or *index*"_doc)

    .def_prop_rw("reserved3",
        nb::overload_cast<>(&Section::reserved3, nb::const_),
        nb::overload_cast<uint32_t>(&Section::reserved3),
        "According to the official ``loader.h`` file, this value is reserved for *offset* or *index*"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&Section::flags, nb::const_),
        nb::overload_cast<uint32_t>(&Section::flags),
        "Section's flags masked with SECTION_FLAGS_MASK (see: :class:`~lief.MachO.MACHO_SECTION_FLAGS`)"_doc)

    .def_prop_ro("flags_list",
        nb::overload_cast<>(&Section::flags_list, nb::const_),
        nb::rv_policy::reference_internal)

    .def_prop_ro("segment",
        nb::overload_cast<>(&Section::segment),
        "" RST_CLASS_REF(lief.MachO.SegmentCommand) " associated with the section or None if not present"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_rw("segment_name",
        nb::overload_cast<>(&Section::segment_name, nb::const_),
        nb::overload_cast<const std::string&>(&Section::segment_name),
        R"delim(The segment name associated with the section)delim"_doc)

    .def_prop_ro("has_segment", &Section::has_segment,
        "True if the current section has a segment associated with"_doc)

    .def("has",
        nb::overload_cast<MACHO_SECTION_FLAGS>(&Section::has, nb::const_),
        "Check if the section has the given " RST_CLASS_REF(lief.MachO.SECTION_FLAGS) ""_doc,
        "flag"_a)

    .def("add",
        nb::overload_cast<MACHO_SECTION_FLAGS>(&Section::add),
        "Add the given " RST_CLASS_REF(lief.MachO.SECTION_FLAGS) ""_doc,
        "flag"_a)

    .def("remove",
        nb::overload_cast<MACHO_SECTION_FLAGS>(&Section::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.SECTION_FLAGS) ""_doc,
        "flag"_a)

    .def(nb::self += MACHO_SECTION_FLAGS(), nb::rv_policy::reference_internal)
    .def(nb::self -= MACHO_SECTION_FLAGS(), nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<MACHO_SECTION_FLAGS>(&Section::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.MachO.MACHO_SECTION_FLAGS) " is present"_doc)

    LIEF_DEFAULT_STR(Section);

}

}
