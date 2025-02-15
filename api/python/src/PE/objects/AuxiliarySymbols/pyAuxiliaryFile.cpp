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

#include "LIEF/PE/AuxiliarySymbols/AuxiliaryFile.hpp"

#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<AuxiliaryFile>(nb::module_& m) {
  nb::class_<AuxiliaryFile, AuxiliarySymbol> aux(m, "AuxiliaryFile",
    R"doc(
    This auxiliary symbol represents a filename (auxiliary format 4)

    The :attr:`lief.Symbol.name` itself should start with ``.file``, and this
    auxiliary record gives the name of a source-code file.

    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-4-files
    )doc"_doc
  );

  aux
    .def_prop_ro("filename", nb::overload_cast<>(&AuxiliaryFile::filename, nb::const_),
                 "The associated filename"_doc)
  ;
}

}
