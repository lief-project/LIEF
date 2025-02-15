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

#include "LIEF/PE/AuxiliarySymbols/AuxiliaryFunctionDefinition.hpp"

namespace LIEF::PE::py {

template<>
void create<AuxiliaryFunctionDefinition>(nb::module_& m) {
  nb::class_<AuxiliaryFunctionDefinition, AuxiliarySymbol>(m, "AuxiliaryFunctionDefinition",
    R"doc(
    This auxiliary symbol marks the beginning of a function definition.

    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-1-function-definitions
    )doc"_doc
  )
    .def_prop_ro("tag_index",
      nb::overload_cast<>(&AuxiliaryFunctionDefinition::tag_index, nb::const_),
      R"doc(
      The symbol-table index of the corresponding ``.bf`` (begin function)
      symbol record.
      )doc"_doc
    )

    .def_prop_ro("total_size",
      nb::overload_cast<>(&AuxiliaryFunctionDefinition::total_size, nb::const_),
      R"doc(
      The size of the executable code for the function itself.

      If the function is in its own section, the ``SizeOfRawData`` in the section
      header is greater or equal to this field, depending on alignment consideration
      )doc"_doc
    )

    .def_prop_ro("ptr_to_line_number",
      nb::overload_cast<>(&AuxiliaryFunctionDefinition::ptr_to_line_number, nb::const_),
      R"doc(
      The file offset of the first COFF line-number entry for the function,
      or zero if none exists (deprecated)
      )doc"_doc
    )

    .def_prop_ro("ptr_to_next_func",
      nb::overload_cast<>(&AuxiliaryFunctionDefinition::ptr_to_next_func, nb::const_),
      R"doc(
      The symbol-table index of the record for the next function. If the function
      is the last in the symbol table, this field is set to zero
      )doc"_doc
    )

    .def_prop_ro("padding",
      nb::overload_cast<>(&AuxiliaryFunctionDefinition::padding, nb::const_),
      "Padding value (should be 0)"_doc
    )
  ;
}

}
