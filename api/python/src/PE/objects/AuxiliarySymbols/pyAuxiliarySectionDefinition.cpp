/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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

#include "LIEF/PE/AuxiliarySymbols/AuxiliarySectionDefinition.hpp"

namespace LIEF::PE::py {

template<>
void create<AuxiliarySectionDefinition>(nb::module_& m) {
  nb::class_<AuxiliarySectionDefinition, AuxiliarySymbol>(m, "AuxiliarySectionDefinition",
    R"doc(
    This auxiliary symbol exposes information about the associated section.

    It **duplicates** some information that are provided in the section header
    )doc"_doc
  )
    .def_prop_ro("length", nb::overload_cast<>(&AuxiliarySectionDefinition::length, nb::const_),
      R"doc(
      The size of section data. The same as ``SizeOfRawData`` in the section header.
      )doc"_doc
    )

    .def_prop_ro("nb_relocs", nb::overload_cast<>(&AuxiliarySectionDefinition::nb_relocs, nb::const_),
      R"doc(
      The number of relocation entries for the section.
      )doc"_doc
    )

    .def_prop_ro("nb_line_numbers", nb::overload_cast<>(&AuxiliarySectionDefinition::nb_line_numbers, nb::const_),
      R"doc(
      The number of line-number entries for the section.
      )doc"_doc
    )

    .def_prop_ro("checksum", nb::overload_cast<>(&AuxiliarySectionDefinition::checksum, nb::const_),
      R"doc(
      The checksum for communal data. It is applicable if the
      ``IMAGE_SCN_LNK_COMDAT`` flag is set in the section header.
      )doc"_doc
    )

    .def_prop_ro("section_idx", nb::overload_cast<>(&AuxiliarySectionDefinition::section_idx, nb::const_),
      R"doc(
      One-based index into the section table for the associated section.
      This is used when the COMDAT selection setting is 5.
      )doc"_doc
    )

    .def_prop_ro("selection", nb::overload_cast<>(&AuxiliarySectionDefinition::selection, nb::const_),
      R"doc(
      The COMDAT selection number. This is applicable if the section is a COMDAT
      section.
      )doc"_doc
    )
  ;
}

}
