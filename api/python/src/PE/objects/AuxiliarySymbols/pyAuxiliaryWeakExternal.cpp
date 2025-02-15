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

#include "nanobind/extra/stl/lief_span.h"

#include "LIEF/PE/AuxiliarySymbols/AuxiliaryWeakExternal.hpp"

namespace LIEF::PE::py {

template<>
void create<AuxiliaryWeakExternal>(nb::module_& m) {
  nb::class_<AuxiliaryWeakExternal, AuxiliarySymbol> aux(m, "AuxiliaryWeakExternal",
    R"doc(
    "Weak externals" are a mechanism for object files that allows flexibility at
    link time. A module can contain an unresolved external symbol (``sym1``), but
    it can also include an auxiliary record that indicates that if ``sym1`` is not
    present at link time, another external symbol (``sym2``) is used to resolve
    references instead.

    If a definition of ``sym1`` is linked, then an external reference to the
    symbol is resolved normally. If a definition of ``sym1`` is not linked, then all
    references to the weak external for ``sym1`` refer to ``sym2`` instead. The external
    symbol, ``sym2``, must always be linked; typically, it is defined in the module
    that contains the weak reference to ``sym1``.

    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-3-weak-externals
    )doc"_doc
  );

  nb::enum_<AuxiliaryWeakExternal::CHARACTERISTICS>(aux, "CHARACTERISTICS")
    .value("SEARCH_NOLIBRARY", AuxiliaryWeakExternal::CHARACTERISTICS::SEARCH_NOLIBRARY)
    .value("SEARCH_LIBRARY", AuxiliaryWeakExternal::CHARACTERISTICS::SEARCH_LIBRARY)
    .value("SEARCH_ALIAS", AuxiliaryWeakExternal::CHARACTERISTICS::SEARCH_ALIAS)
    .value("ANTI_DEPENDENCY", AuxiliaryWeakExternal::CHARACTERISTICS::ANTI_DEPENDENCY);

  aux
    .def_prop_ro("sym_idx", nb::overload_cast<>(&AuxiliaryWeakExternal::sym_idx, nb::const_),
      R"doc(
      The symbol-table index of sym2, the symbol to be linked if ``sym1`` is not
      found.
      )doc"_doc
    )

    .def_prop_ro("characteristics", nb::overload_cast<>(&AuxiliaryWeakExternal::characteristics, nb::const_))
    .def_prop_ro("padding", nb::overload_cast<>(&AuxiliaryWeakExternal::padding, nb::const_))
  ;
}

}
