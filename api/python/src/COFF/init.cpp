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
#include "COFF/init.hpp"
#include "COFF/pyCOFF.hpp"

namespace LIEF::COFF {
class ParserConfig;
class Parser;
class Binary;
class Header;
class String;
class RegularHeader;
class BigObjHeader;
class Symbol;
class Section;
class Relocation;
class AuxiliarySymbol;
}

namespace LIEF::COFF::py {

void init(nb::module_& m) {
  nb::module_ coff_mod = m.def_submodule("COFF", "Python API for the COFF format");
  init_utils(coff_mod);

  create<Header>(coff_mod);
  create<Binary>(coff_mod);
  create<ParserConfig>(coff_mod);
  create<Parser>(coff_mod);
  create<String>(coff_mod);
  create<Symbol>(coff_mod);
  create<Section>(coff_mod);
  create<Relocation>(coff_mod);
  create<AuxiliarySymbol>(coff_mod);
}
}
