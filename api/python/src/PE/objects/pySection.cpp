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
#include "PE/pyPE.hpp"

#include "LIEF/PE/Section.hpp"
#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/vector.h>
#include "nanobind/utils.hpp"


#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {

template<>
void create<Section>(nb::module_& m) {
  nb::class_<Section, LIEF::Section> sec(m, "Section",
      R"delim(
      Class which represents a PE section.

      It extends the base class :class:`lief.Section`
      )delim"_doc);

  enum_<Section::CHARACTERISTICS>(sec, "CHARACTERISTICS", nb::is_arithmetic())
    .value(PY_ENUM(Section::CHARACTERISTICS::TYPE_NO_PAD))
    .value(PY_ENUM(Section::CHARACTERISTICS::CNT_CODE))
    .value(PY_ENUM(Section::CHARACTERISTICS::CNT_INITIALIZED_DATA))
    .value(PY_ENUM(Section::CHARACTERISTICS::CNT_UNINITIALIZED_DATA))
    .value(PY_ENUM(Section::CHARACTERISTICS::LNK_OTHER))
    .value(PY_ENUM(Section::CHARACTERISTICS::LNK_INFO))
    .value(PY_ENUM(Section::CHARACTERISTICS::LNK_REMOVE))
    .value(PY_ENUM(Section::CHARACTERISTICS::LNK_COMDAT))
    .value(PY_ENUM(Section::CHARACTERISTICS::GPREL))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_PURGEABLE))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_16BIT))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_LOCKED))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_PRELOAD))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_1BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_2BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_4BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_8BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_16BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_32BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_64BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_128BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_256BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_512BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_1024BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_2048BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_4096BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::ALIGN_8192BYTES))
    .value(PY_ENUM(Section::CHARACTERISTICS::LNK_NRELOC_OVFL))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_DISCARDABLE))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_NOT_CACHED))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_NOT_PAGED))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_SHARED))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_EXECUTE))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_READ))
    .value(PY_ENUM(Section::CHARACTERISTICS::MEM_WRITE));

  sec
    .def(nb::init<>())
    .def(nb::init<const std::vector<uint8_t>&, const std::string&, uint32_t>(),
        "Constructor from "
        ":attr:`~lief.PE.Section.content`, "
        ":attr:`~lief.PE.Section.name` and "
        ":attr:`~lief.PE.Section.characteristics`"_doc,
        "content"_a, nb::arg("name") = "", nb::arg("characteristics") = 0)

    .def(nb::init<const std::string&>(),
        "Constructor from a "
        ":attr:`~lief.PE.Section.name`"_doc,
        "name"_a)

    .def_prop_rw("virtual_size",
        nb::overload_cast<>(&Section::virtual_size, nb::const_),
        nb::overload_cast<uint32_t>(&Section::virtual_size),
        R"delim(
        The total size of the section when loaded into memory.

        If this value is greater than :attr:`~lief.PE.Section.sizeof_raw_data`,
        the section is zero-padded.
        )delim"_doc)

    .def_prop_rw("sizeof_raw_data",
        nb::overload_cast<>(&Section::sizeof_raw_data, nb::const_),
        nb::overload_cast<uint32_t>(&Section::sizeof_raw_data),
        "Alias of :attr:`~lief.PE.Section.size` (size of the data in the section)"_doc)

    .def_prop_rw("pointerto_raw_data",
        nb::overload_cast<>(&Section::pointerto_raw_data, nb::const_),
        nb::overload_cast<uint32_t>(&Section::pointerto_raw_data),
        "The offset of the section data in the PE file. Alias of :attr:`~lief.PE.Section.offset`"_doc)

    .def_prop_rw("pointerto_relocation",
        nb::overload_cast<>(&Section::pointerto_relocation, nb::const_),
        nb::overload_cast<uint32_t>(&Section::pointerto_relocation),
        R"delim(
        The file pointer to the beginning of the COFF relocation entries for
        the section. This is set to zero for executable images or if there are
        no relocations.

        For modern PE binaries, this value is usually set to 0 as the relocations are managed by
        :class:`~lief.PE.Relocation`.
        )delim"_doc)

    .def_prop_rw("pointerto_line_numbers",
        nb::overload_cast<>(&Section::pointerto_line_numbers, nb::const_),
        nb::overload_cast<uint32_t>(&Section::pointerto_line_numbers),
        R"delim(
        The file pointer to the beginning of line-number entries for the section.
        This is set to zero if there are no COFF line numbers. This value should
        be zero for an image because COFF debugging information is deprecated
        and modern debug information relies on the PDB files.
        )delim"_doc)

    .def_prop_rw("numberof_relocations",
        nb::overload_cast<>(&Section::numberof_relocations, nb::const_),
        nb::overload_cast<uint16_t>(&Section::numberof_relocations),
        R"delim(
        The number of relocation entries for the section.

        See: :attr:`~lief.PE.Section.pointerto_relocation`
        )delim"_doc)

    .def_prop_rw("numberof_line_numbers",
        nb::overload_cast<>(&Section::numberof_line_numbers, nb::const_),
        nb::overload_cast<uint16_t>(&Section::numberof_line_numbers),
        R"delim(
        The number of line-number entries for the section.
        This value should be zero for an image because COFF debugging information is
        deprecated.

        See: :attr:`~lief.PE.Section.pointerto_line_numbers`
        )delim"_doc)


    .def_prop_rw("characteristics",
        nb::overload_cast<>(&Section::characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&Section::characteristics),
        "The " RST_CLASS_REF(lief.PE.Section.CHARACTERISTICS) "  that describe the characteristics of the section"_doc)

    .def_prop_ro("characteristics_lists",
        &Section::characteristics_list,
        ":attr:`~lief.PE.Section.characteristics` as a ``list``"_doc)

    .def("has_characteristic",
        &Section::has_characteristic,
        "``True`` if the section has the given " RST_CLASS_REF(lief.PE.Section.CHARACTERISTICS) ""_doc,
        "characteristic"_a)

    .def_prop_ro("padding",
        [] (const Section& sec) {
          return nb::to_bytes(sec.padding());
        },
        "Section padding content as bytes"_doc)

    LIEF_COPYABLE(Section)
    LIEF_DEFAULT_STR(Section);
}

}
