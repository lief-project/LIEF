/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "COFF/pyCOFF.hpp"

#include "LIEF/COFF/Section.hpp"
#include "LIEF/COFF/Relocation.hpp"
#include "LIEF/COFF/Symbol.hpp"
#include "LIEF/COFF/String.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/lief_optional.h>

#include "nanobind/utils.hpp"

#include "pyIterator.hpp"

namespace LIEF::COFF::py {

template<>
void create<Section>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<Section, LIEF::Section> sec(m, "Section",
    R"doc(
    This class represents a COFF section
    )doc"_doc);

  init_ref_iterator<Section::it_relocations>(sec, "it_relocations");
  init_ref_iterator<Section::it_symbols>(sec, "it_symbols");

  nb::class_<Section::ComdatInfo>(sec, "ComdatInfo",
    R"doc(
    This class wraps comdat information which is composed of the symbol associated
    with the comdat section and its selection flag
    )doc"_doc
  )
    .def_ro("symbol", &Section::ComdatInfo::symbol)
    .def_ro("kind", &Section::ComdatInfo::kind)
  ;

  sec
    .def_prop_rw("virtual_size",
      nb::overload_cast<>(&Section::virtual_size, nb::const_),
      nb::overload_cast<uint32_t>(&Section::virtual_size),
      "Virtual size of the section (should be 0)"_doc)

    .def_prop_rw("sizeof_raw_data",
      nb::overload_cast<>(&Section::sizeof_raw_data, nb::const_),
      nb::overload_cast<uint32_t>(&Section::sizeof_raw_data),
      "Return the size of the data in the section."_doc)

    .def_prop_rw("pointerto_raw_data",
      nb::overload_cast<>(&Section::pointerto_raw_data, nb::const_),
      nb::overload_cast<uint32_t>(&Section::pointerto_raw_data),
      "Offset to the section's content"_doc)

    .def_prop_rw("pointerto_relocation",
      nb::overload_cast<>(&Section::pointerto_relocation, nb::const_),
      nb::overload_cast<uint32_t>(&Section::pointerto_relocation),
      "Offset to the relocation table"_doc)

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
      Number of relocations.

      .. warning::

        If the number of relocations is greater than 0xFFFF (maximum value for
        16-bits integer), then the number of relocations is stored in the
        virtual address attribute.
      )delim"_doc)

    .def_prop_rw("numberof_line_numbers",
      nb::overload_cast<>(&Section::numberof_line_numbers, nb::const_),
      nb::overload_cast<uint16_t>(&Section::numberof_line_numbers),
      R"delim(
      The number of line-number entries for the section.
      This value should be zero for an image because COFF debugging information is
      deprecated.

      See: :attr:`~lief.COFF.Section.pointerto_line_numbers`
      )delim"_doc)

    .def_prop_rw("characteristics",
      nb::overload_cast<>(&Section::characteristics, nb::const_),
      nb::overload_cast<uint32_t>(&Section::characteristics),
      "The characteristics  that describe the purpose of the section"_doc)

    .def_prop_ro("characteristics_lists",
      &Section::characteristics_list,
      "characteristics as a ``list``"_doc)

    .def("has_characteristic", &Section::has_characteristic,
      "``True`` if the section has the given characteristic"_doc,
      "characteristic"_a)

    .def_prop_ro("is_discardable", &Section::is_discardable,
      R"doc(
      True if the section can be discarded as needed.

      This is typically the case for debug-related sections.
      )doc"_doc
    )

    .def_prop_ro("relocations",
      nb::overload_cast<>(&Section::relocations),
      "Iterator over the relocations performed in this section"_doc,
      nb::keep_alive<0, 1>()
    )

    .def_prop_ro("symbols",
      nb::overload_cast<>(&Section::symbols),
      "Iterator over the symbols associated with this section"_doc,
      nb::keep_alive<0, 1>()
    )

    .def_prop_ro("has_extended_relocations",
      &Section::has_extended_relocations,
      R"doc(
      Whether there is a large number of relocations whose number need to be
      stored in the virtual address attribute
      )doc"_doc
    )

    .def_prop_ro("comdat_info", &Section::comdat_info,
      R"doc(
      Return comdat infomration (only if the section has the
      :attr:`lief.PE.Section.CHARACTERISTICS.LNK_COMDAT` characteristic)
      )doc"_doc
    )

    .def_prop_ro("coff_string", nb::overload_cast<>(&Section::coff_string),
      R"doc(
      Return the COFF string associated with the section's name (or None)

      This coff string is usually present for long section names whose length
      does not fit in the 8 bytes allocated by the COFF format.
      )doc"_doc
    )

    LIEF_DEFAULT_STR(Section);
}

}
