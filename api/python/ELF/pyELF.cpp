/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyELF.hpp"


namespace LIEF {
namespace ELF {
void init_python_module(py::module& m) {
  py::module LIEF_ELF_module = m.def_submodule("ELF", "Python API for the ELF format");

  init_enums(LIEF_ELF_module);
  init_objects(LIEF_ELF_module);

  py::module LIEF_ELF32_module = LIEF_ELF_module.def_submodule("ELF32", "");
  init_ELF32_sizes(LIEF_ELF32_module);

  py::module LIEF_ELF64_module = LIEF_ELF_module.def_submodule("ELF64", "");
  init_ELF64_sizes(LIEF_ELF64_module);
}

void init_objects(py::module& m) {
  CREATE(Parser, m);
  CREATE(SymbolVersion, m);
  CREATE(Binary, m);
  CREATE(Header, m);
  CREATE(Section, m);
  CREATE(Segment, m);
  CREATE(Symbol, m);
  CREATE(Relocation, m);
  CREATE(SymbolVersionAux, m);
  CREATE(SymbolVersionAuxRequirement, m);
  CREATE(SymbolVersionDefinition,m );
  CREATE(SymbolVersionRequirement, m);
  CREATE(DynamicEntry, m);
  CREATE(DynamicEntryLibrary, m);
  CREATE(DynamicSharedObject, m);
  CREATE(DynamicEntryArray, m);
  CREATE(DynamicEntryRpath, m);
  CREATE(DynamicEntryRunPath, m);
  CREATE(DynamicEntryFlags, m);
  CREATE(GnuHash, m);
  CREATE(SysvHash, m);
  CREATE(Builder, m);
  CREATE(Note, m);
  CREATE(NoteDetails, m);
  CREATE(AndroidNote, m);
  CREATE(NoteAbi, m);
  CREATE(CorePrPsInfo, m);
  CREATE(CoreFile, m);
  CREATE(CoreFileEntry, m);
  CREATE(CorePrStatus, m);
  CREATE(CoreAuxv, m);
  CREATE(CoreSigInfo, m);
}

}
}
