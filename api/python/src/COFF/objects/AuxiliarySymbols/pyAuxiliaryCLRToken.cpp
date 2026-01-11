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

#include "LIEF/COFF/AuxiliarySymbols/AuxiliaryCLRToken.hpp"
#include "LIEF/COFF/Symbol.hpp"
#include "nanobind/extra/stl/lief_span.h"

namespace LIEF::COFF::py {

template<>
void create<AuxiliaryCLRToken>(nb::module_& m) {
  nb::class_<AuxiliaryCLRToken, AuxiliarySymbol> aux(m, "AuxiliaryCLRToken",
    R"doc(
    Auxiliary symbol associated with the ``CLR_TOKEN`` storage class
    )doc"_doc
  );

  aux
    .def_prop_ro("aux_type", &AuxiliaryCLRToken::aux_type,
      "``IMAGE_AUX_SYMBOL_TYPE`` which should be ``IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF`` (1)"_doc
    )

    .def_prop_ro("reserved", &AuxiliaryCLRToken::reserved,
      "Reserved value (should be 0)"_doc
    )

    .def_prop_ro("symbol_idx", &AuxiliaryCLRToken::symbol_idx,
      "Index in the symbol table"_doc
    )

    .def_prop_ro("symbol", nb::overload_cast<>(&AuxiliaryCLRToken::symbol),
      "Symbol referenced by :attr:`~.symbol_idx` (if resolved)"_doc
    )

    .def_prop_ro("rgb_reserved", &AuxiliaryCLRToken::rgb_reserved,
      "Reserved (padding) values. Should be 0"_doc
    )
  ;
}

}
