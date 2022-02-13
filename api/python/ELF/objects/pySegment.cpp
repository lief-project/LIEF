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
#include <vector>


#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Section.hpp"

#include "pyIterators.hpp"
#include "pyELF.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (Segment::*)(void) const;

template<class T>
using setter_t = void (Segment::*)(T);

template<class T>
using no_const_getter = T (Segment::*)(void);


template<>
void create<Segment>(py::module& m) {
  py::class_<Segment, LIEF::Object> seg(m, "Segment",
      R"delim(
      Class which represents the ELF segments
      )delim");

  init_ref_iterator<Segment::it_sections>(seg, "it_sections");

  seg
    .def(py::init<>())
    .def_static("from_raw",
        [] (py::bytes raw) -> py::object {
          const std::string& bytes_as_str = raw;
          std::vector<uint8_t> cpp_raw = {std::begin(bytes_as_str), std::end(bytes_as_str)};
          auto* f_ptr = static_cast<result<Segment>(*)(const std::vector<uint8_t>&)>(&Segment::from_raw);
          return error_or(f_ptr, std::move(cpp_raw));
        })

    .def_property("type",
        static_cast<getter_t<SEGMENT_TYPES>>(&Segment::type),
        static_cast<setter_t<SEGMENT_TYPES>>(&Segment::type),
        "Segment's type: " RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) "")

    .def_property("flags",
        static_cast<getter_t<ELF_SEGMENT_FLAGS>>(&Segment::flags),
        static_cast<setter_t<ELF_SEGMENT_FLAGS>>(&Segment::flags),
        "The flag permissions associated with this segment")

    .def_property("file_offset",
        static_cast<getter_t<uint64_t>>(&Segment::file_offset),
        static_cast<setter_t<uint64_t>>(&Segment::file_offset),
        "The file offset of the data associated with this segment")

    .def_property("virtual_address",
        static_cast<getter_t<uint64_t>>(&Segment::virtual_address),
        static_cast<setter_t<uint64_t>>(&Segment::virtual_address),
        R"delim(
        The virtual address of the segment.

        .. warning::
            The ELF format specifications require the following relationship:

            .. math::
                \text{virtual address} \equiv \text{file offset} \pmod{\text{page size}}
                \text{virtual address} \equiv \text{file offset} \pmod{\text{alignment}}
        )delim")

    .def_property("physical_address",
        static_cast<getter_t<uint64_t>>(&Segment::physical_address),
        static_cast<setter_t<uint64_t>>(&Segment::physical_address),
        R"delim(
        The physical address of the segment.
        This value is not really relevant on systems like Linux or Android. On the other hand,
        Qualcomm trustlets might use this value.

        Usually this value matches :attr:`~lief.ELF.Segment.virtual_address`
        )delim")

    .def_property("physical_size",
        static_cast<getter_t<uint64_t>>(&Segment::physical_size),
        static_cast<setter_t<uint64_t>>(&Segment::physical_size),
        "The **file** size of the data associated with this segment")

    .def_property("virtual_size",
        static_cast<getter_t<uint64_t>>(&Segment::virtual_size),
        static_cast<setter_t<uint64_t>>(&Segment::virtual_size),
        R"delim(
        The in-memory size of this segment.

        Usually, if the ``.bss`` segment is wrapped by this segment
        then, virtual_size is larger than physical_size
        )delim")

    .def_property("alignment",
        static_cast<getter_t<uint64_t>>(&Segment::alignment),
        static_cast<setter_t<uint64_t>>(&Segment::alignment),
        "The offset alignment of the segment")

    .def_property("content",
        [] (const Segment& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        },
        static_cast<setter_t<std::vector<uint8_t>>>(&Segment::content),
        "The raw data associated with this segment.")

    .def("add",
        &Segment::add,
        "Add the given " RST_CLASS_REF(lief.ELF.SEGMENT_FLAGS) " to the list of "
        ":attr:`~lief.ELF.Segment.flags`",
        "flag"_a)

    .def("remove",
        &Segment::remove,
        "Remove the given " RST_CLASS_REF(lief.ELF.SEGMENT_FLAGS) " from the list of "
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
      static_cast<no_const_getter<Segment::it_sections>>(&Segment::sections),
      "Iterator over the " RST_CLASS_REF(lief.ELF.Section) " wrapped by this segment",
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

}
}
