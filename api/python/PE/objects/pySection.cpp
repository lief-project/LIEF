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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/PE/Section.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Section::*)(void) const;

template<class T>
using setter_t = void (Section::*)(T);


template<>
void create<Section>(py::module& m) {
  py::class_<Section, LIEF::Section>(m, "Section",
      R"delim(
      Class which represents a PE section.

      It extends the base class :class:`lief.Section`
      )delim")
    .def(py::init<>())
    .def(py::init<const std::vector<uint8_t>&, const std::string&, uint32_t>(),
        "Constructor from "
        ":attr:`~lief.PE.Section.content`, "
        ":attr:`~lief.PE.Section.name` and "
        ":attr:`~lief.PE.Section.characteristics`",
        "content"_a, py::arg("name") = "", py::arg("characteristics") = 0)

    .def(py::init<const std::string&>(),
        "Constructor from a "
        ":attr:`~lief.PE.Section.name`",
        "name"_a)

    .def_property("virtual_size",
        static_cast<getter_t<uint32_t>>(&Section::virtual_size),
        static_cast<setter_t<uint32_t>>(&Section::virtual_size),
        R"delim(
        The total size of the section when loaded into memory.

        If this value is greater than :attr:`~lief.PE.Section.sizeof_raw_data`, the section is zero-padded.
        )delim")

    .def_property("sizeof_raw_data",
        static_cast<getter_t<uint32_t>>(&Section::sizeof_raw_data),
        static_cast<setter_t<uint32_t>>(&Section::sizeof_raw_data),
        "Alias of :attr:`~lief.PE.Section.size` (size of the data in the section)")

    .def_property("pointerto_raw_data",
        static_cast<getter_t<uint32_t>>(&Section::pointerto_raw_data),
        static_cast<setter_t<uint32_t>>(&Section::pointerto_raw_data),
        "The offset of the section data in the PE file. Alias of :attr:`~lief.PE.Section.offset`")

    .def_property("pointerto_relocation",
        static_cast<getter_t<uint32_t>>(&Section::pointerto_relocation),
        static_cast<setter_t<uint32_t>>(&Section::pointerto_relocation),
        R"delim(
        The file pointer to the beginning of the COFF relocation entries for the section. This is set to zero for
        executable images or if there are no relocations.

        For modern PE binaries, this value is usually set to 0 as the relocations are managed by
        :class:`~lief.PE.Relocation`.
        )delim")

    .def_property("pointerto_line_numbers",
        static_cast<getter_t<uint32_t>>(&Section::pointerto_line_numbers),
        static_cast<setter_t<uint32_t>>(&Section::pointerto_line_numbers),
        R"delim(
        The file pointer to the beginning of line-number entries for the section.
        This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF
        debugging information is deprecated and modern debug information relies on the PDB files.
        )delim")

    .def_property("numberof_relocations",
        static_cast<getter_t<uint16_t>>(&Section::numberof_relocations),
        static_cast<setter_t<uint16_t>>(&Section::numberof_relocations),
        R"delim(
        The number of relocation entries for the section.

        See: :attr:`~lief.PE.Section.pointerto_relocation`
        )delim")

    .def_property("numberof_line_numbers",
        static_cast<getter_t<uint16_t>>(&Section::numberof_line_numbers),
        static_cast<setter_t<uint16_t>>(&Section::numberof_line_numbers),
        R"delim(
        The number of line-number entries for the section.
        This value should be zero for an image because COFF debugging information is
        deprecated.

        See: :attr:`~lief.PE.Section.pointerto_line_numbers`
        )delim")


    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&Section::characteristics),
        static_cast<setter_t<uint32_t>>(&Section::characteristics),
        "The " RST_CLASS_REF(lief.PE.SECTION_CHARACTERISTICS) "  that describe the characteristics of the section")

    .def_property_readonly("characteristics_lists",
        &Section::characteristics_list,
        ":attr:`~lief.PE.Section.characteristics` as a ``list``")

    .def("has_characteristic",
        &Section::has_characteristic,
        "``True`` if the section has the given " RST_CLASS_REF(lief.PE.SECTION_CHARACTERISTICS) "",
        "characteristic"_a)

    .def_property_readonly("padding",
        [] (const Section& sec) {
          const std::vector<uint8_t>& data = sec.padding();
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Section padding content as bytes")

    .def("__eq__", &Section::operator==)
    .def("__ne__", &Section::operator!=)
    .def("__hash__",
        [] (const Section& section) {
          return Hash::hash(section);
        })

    .def("__str__",
        [] (const Section& section) {
          std::ostringstream stream;
          stream << section;
          std::string str =  stream.str();
          return str;
        });
}

}
}
