/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "ELF/init.hpp"
#include "ELF/enums.hpp"
#include "ELF/pyELF.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "LIEF/ELF/Builder.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/GnuHash.hpp"
#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/SysvHash.hpp"
#include "LIEF/ELF/utils.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/AndroidIdent.hpp"
#include "LIEF/ELF/NoteDetails/QNXStack.hpp"
#include "LIEF/ELF/NoteDetails/NoteAbi.hpp"
#include "LIEF/ELF/NoteDetails/NoteGnuProperty.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreAuxv.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreFile.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"
#include "LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::ELF::py {

void init_notes(nb::module_& m) {
  CREATE(Note, m);
  CREATE(NoteGnuProperty, m);
  CREATE(AndroidIdent, m);
  CREATE(NoteAbi, m);
  CREATE(CoreAuxv, m);
  CREATE(CoreFile, m);
  CREATE(CorePrPsInfo, m);
  CREATE(CoreSigInfo, m);
  CREATE(CorePrStatus, m);
  CREATE(QNXStack, m);
}

void init_objects(nb::module_& m) {
  CREATE(ParserConfig, m);
  CREATE(Parser, m);
  CREATE(SymbolVersion, m);
  CREATE(Binary, m);
  CREATE(PROCESSOR_FLAGS, m);
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

  init_notes(m);
}

inline void init_utils(nb::module_&) {
  lief_mod->def("is_elf",
      nb::overload_cast<const std::string&>(&is_elf),
      "Check if the given file is an ``ELF``",
      "filename"_a);

  lief_mod->def("is_elf",
      nb::overload_cast<const std::vector<uint8_t>&>(&is_elf),
      "Check if the given raw data is an ``ELF``",
      "raw"_a);
}

void init(nb::module_& m) {
  nb::module_ elf_mod = m.def_submodule("ELF", "Python API for the ELF format");
  init_utils(m);
  init_enums(elf_mod);
  init_objects(elf_mod);
}
}
