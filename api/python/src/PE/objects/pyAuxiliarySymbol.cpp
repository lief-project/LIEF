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
#include "pyLIEF.hpp"
#include "PE/pyPE.hpp"

#include "LIEF/PE/AuxiliarySymbol.hpp"

#include <string>
#include <sstream>

#include "enums_wrapper.hpp"

#include "nanobind/extra/stl/lief_span.h"
#include "nanobind/stl/unique_ptr.h"

namespace LIEF::PE {
class AuxiliaryCLRToken;
class AuxiliaryFunctionDefinition;
class AuxiliaryWeakExternal;
class AuxiliarybfAndefSymbol;
class AuxiliarySectionDefinition;
class AuxiliaryFile;
}

namespace LIEF::PE::py {

template<>
void create<AuxiliarySymbol>(nb::module_& m) {
  nb::class_<AuxiliarySymbol> aux(m, "AuxiliarySymbol",
    R"doc(
    Class that represents an auxiliary symbol.

    An auxiliary symbol has the same size as a regular :class:`lief.PE.Symbol`
    (18 bytes) but its content depends on the the parent symbol.
    )doc"_doc
  );

  enum_<AuxiliarySymbol::TYPE>(aux, "TYPE",
    "Type discriminator for the subclasses"_doc
  )
    .value("UNKNOWN", AuxiliarySymbol::TYPE::UNKNOWN)
    .value("CLR_TOKEN", AuxiliarySymbol::TYPE::CLR_TOKEN)
    .value("FUNC_DEF", AuxiliarySymbol::TYPE::FUNC_DEF)
    .value("BF_AND_EF", AuxiliarySymbol::TYPE::BF_AND_EF)
    .value("WEAK_EXTERNAL", AuxiliarySymbol::TYPE::WEAK_EXTERNAL)
    .value("FILE", AuxiliarySymbol::TYPE::FILE)
    .value("SEC_DEF", AuxiliarySymbol::TYPE::SEC_DEF);

  aux
    .def_prop_ro("type", &AuxiliarySymbol::type)
    .def_prop_ro("payload", nb::overload_cast<>(&AuxiliarySymbol::payload),
                 "For unknown type **only**, return the raw representation of this symbol"_doc)

  LIEF_DEFAULT_STR(AuxiliarySymbol)
  LIEF_CLONABLE(AuxiliarySymbol);

  create<AuxiliaryCLRToken>(m);
  create<AuxiliaryFunctionDefinition>(m);
  create<AuxiliaryWeakExternal>(m);
  create<AuxiliarybfAndefSymbol>(m);
  create<AuxiliarySectionDefinition>(m);
  create<AuxiliaryFile>(m);
}

}
