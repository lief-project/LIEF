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

#include "LIEF/COFF/AuxiliarySymbols/AuxiliarySectionDefinition.hpp"

namespace LIEF::COFF::py {

template<>
void create<AuxiliarySectionDefinition>(nb::module_& m) {
  nb::class_<AuxiliarySectionDefinition, AuxiliarySymbol> aux(m, "AuxiliarySectionDefinition",
    R"doc(
    This auxiliary symbol exposes information about the associated section.

    It **duplicates** some information that are provided in the section header
    )doc"_doc
  );

  using COMDAT_SELECTION = AuxiliarySectionDefinition::COMDAT_SELECTION;
  nb::enum_<AuxiliarySectionDefinition::COMDAT_SELECTION>(aux, "COMDAT_SELECTION",
    R"doc(
    Values for the AuxiliarySectionDefinition::selection attribute

    See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#comdat-sections-object-only
    )doc"_doc
  )
    .value("NONE", COMDAT_SELECTION::NONE)
    .value("NODUPLICATES", COMDAT_SELECTION::NODUPLICATES,
      R"doc(
      If this symbol is already defined, the linker issues a
      ``multiply defined symbol`` error.
      )doc"_doc
    )

    .value("ANY", COMDAT_SELECTION::ANY,
      R"doc(
      Any section that defines the same COMDAT symbol can be linked; the rest
      are removed.
      )doc"_doc
    )

    .value("SAME_SIZE", COMDAT_SELECTION::SAME_SIZE,
      R"doc(
      The linker chooses an arbitrary section among the definitions for this
      symbol. If all definitions are not the same size, a ``multiply defined symbol``
      error is issued.
      )doc"_doc
    )

    .value("EXACT_MATCH", COMDAT_SELECTION::EXACT_MATCH,
      R"doc(
      The linker chooses an arbitrary section among the definitions for this
      symbol. If all definitions do not match exactly, a
      ``multiply defined symbol`` error is issued.
      )doc"_doc
    )

    .value("ASSOCIATIVE", COMDAT_SELECTION::ASSOCIATIVE,
      R"doc(
      The section is linked if a certain other COMDAT section is linked.
      This other section is indicated by the Number field of the auxiliary
      symbol record for the section definition. This setting is useful for
      definitions that have components in multiple sections
      (for example, code in one and data in another), but where all must be
      linked or discarded as a set. The other section this section is
      associated with must be a COMDAT section, which can be another
      associative COMDAT section. An associative COMDAT section's section
      association chain can't form a loop. The section association chain must
      eventually come to a COMDAT section that doesn't have
      :attr:`~.COMDAT_SELECTION.ASSOCIATIVE` set.
      )doc"_doc
    )

    .value("LARGEST", COMDAT_SELECTION::LARGEST,
      R"doc(
      The linker chooses the largest definition from among all of the definitions
      for this symbol. If multiple definitions have this size, the choice
      between them is arbitrary.
      )doc"_doc
    )
  ;

  aux
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

    .def_prop_ro("reserved", nb::overload_cast<>(&AuxiliarySectionDefinition::reserved, nb::const_),
      "Reserved value (should be 0)"_doc
    )
  ;
}

}
