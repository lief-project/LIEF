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
#include <vector>

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Segment.hpp"

#include "pyELF.hpp"

template<class T>
using getter_t = T (Segment::*)(void) const;

template<class T>
using setter_t = void (Segment::*)(T);

template<class T>
using no_const_getter = T (Segment::*)(void);


void init_ELF_Segment_class(py::module& m) {
  py::class_<Segment, LIEF::Object>(m, "Segment")

    .def(py::init<>())
    .def(py::init<const std::vector<uint8_t>&>())
    .def(py::init<const std::vector<uint8_t>&, ELF_CLASS>())

    .def_property("type",
        static_cast<getter_t<SEGMENT_TYPES>>(&Segment::type),
        static_cast<setter_t<SEGMENT_TYPES>>(&Segment::type),
        "Segment's " RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) "")

    .def_property("flags",
        static_cast<getter_t<ELF_SEGMENT_FLAGS>>(&Segment::flags),
        static_cast<setter_t<ELF_SEGMENT_FLAGS>>(&Segment::flags),
        "Segment's flags")

    .def_property("file_offset",
        static_cast<getter_t<uint64_t>>(&Segment::file_offset),
        static_cast<setter_t<uint64_t>>(&Segment::file_offset),
        "Data offset in the binary")

    .def_property("virtual_address",
        static_cast<getter_t<uint64_t>>(&Segment::virtual_address),
        static_cast<setter_t<uint64_t>>(&Segment::virtual_address),
        "Address where the segment will be mapped\n\n"
        ".. warning:: We must have\n\n"
        "\t.. math::\n\n"
        "\t\t\\text{virtual address} \\equiv \\text{file offset} \\pmod{\\text{page size}}\n\n"
        "\t\t\\text{virtual address} \\equiv \\text{file offset} \\pmod{\\text{alignment}}"
        )

    .def_property("physical_address",
        static_cast<getter_t<uint64_t>>(&Segment::physical_address),
        static_cast<setter_t<uint64_t>>(&Segment::physical_address),
        "Physical address of beginning of segment (OS-specific)")

    .def_property("physical_size",
        static_cast<getter_t<uint64_t>>(&Segment::physical_size),
        static_cast<setter_t<uint64_t>>(&Segment::physical_size),
        "Size of data in the binary")

    .def_property("virtual_size",
        static_cast<getter_t<uint64_t>>(&Segment::virtual_size),
        static_cast<setter_t<uint64_t>>(&Segment::virtual_size),
        "Size of this segment in memory")

    .def_property("alignment",
        static_cast<getter_t<uint64_t>>(&Segment::alignment),
        static_cast<setter_t<uint64_t>>(&Segment::alignment),
        "This member gives the value to which the segments are aligned in memory and in the file.\n"
        "Values 0 and 1 mean no alignment is required.")

    .def_property("content",
        static_cast<getter_t<std::vector<uint8_t>>>(&Segment::content),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&Segment::content),
        "Segment's raw data")

    .def("add",
        &Segment::add,
        "Add the given " RST_CLASS_REF(lief.ELF.SEGMENT_FLAGS) " to the list of "
        ":attr:`~lief.ELF.Segment.flags`",
        "flag"_a)

    .def("remove",
        &Segment::remove,
        "Remove the given " RST_CLASS_REF(lief.ELF.SEGMENT_FLAGS) " to the list of "
        ":attr:`~lief.ELF.Segment.flags`",
        "flag"_a)


    .def("has",
        static_cast<bool (Segment::*)(ELF_SEGMENT_FLAGS) const>(&Segment::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.SEGMENT_FLAGS) " is present",
        "flag"_a)

    .def("has",
        static_cast<bool (Segment::*)(const Section&) const>(&Segment::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " is present "
        "in :attr:`~lief.ELF.Segment.sections`",
        "section"_a)

    .def("has",
        static_cast<bool (Segment::*)(const std::string&) const>(&Segment::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " 's name is present "
        "in :attr:`~lief.ELF.Segment.sections`",
        "section_name"_a)

    .def_property_readonly("sections",
      static_cast<no_const_getter<it_sections>>(&Segment::sections),
      "" RST_CLASS_REF(lief.ELF.Section) " (s) inside this segment",
      py::return_value_policy::reference_internal)

    .def("__eq__", &Segment::operator==)
    .def("__ne__", &Segment::operator!=)
    .def("__hash__",
        [] (const Segment& segment) {
          return Hash::hash(segment);
        })

    .def(py::self += ELF_SEGMENT_FLAGS())
    .def(py::self -= ELF_SEGMENT_FLAGS())

    .def("__contains__",
        static_cast<bool (Segment::*)(ELF_SEGMENT_FLAGS) const>(&Segment::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.SEGMENT_FLAGS) " is present")

    .def("__contains__",
        static_cast<bool (Segment::*)(const Section&) const>(&Segment::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " is present "
        "in :attr:`~lief.ELF.Segment.sections`")

    .def("__contains__",
        static_cast<bool (Segment::*)(const std::string&) const>(&Segment::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " 's name is present "
        "in :attr:`~lief.ELF.Segment.sections`")

    .def("__str__",
        [] (const Segment& segment)
        {
          std::ostringstream stream;
          stream << segment;
          std::string str =  stream.str();
          return str;
        });
}
