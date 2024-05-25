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
#include "MachO/init.hpp"
#include "MachO/enums.hpp"
#include "MachO/pyMachO.hpp"

#include <LIEF/MachO/ParserConfig.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/Header.hpp>
#include <LIEF/MachO/LoadCommand.hpp>
#include <LIEF/MachO/UUIDCommand.hpp>
#include <LIEF/MachO/SymbolCommand.hpp>
#include <LIEF/MachO/SegmentCommand.hpp>
#include <LIEF/MachO/Section.hpp>
#include <LIEF/MachO/MainCommand.hpp>
#include <LIEF/MachO/DynamicSymbolCommand.hpp>
#include <LIEF/MachO/DylinkerCommand.hpp>
#include <LIEF/MachO/DyldInfo.hpp>
#include <LIEF/MachO/DyldChainedFixups.hpp>
#include <LIEF/MachO/DyldExportsTrie.hpp>
#include <LIEF/MachO/DylibCommand.hpp>
#include <LIEF/MachO/ThreadCommand.hpp>
#include <LIEF/MachO/RPathCommand.hpp>
#include <LIEF/MachO/Symbol.hpp>
#include <LIEF/MachO/Relocation.hpp>
#include <LIEF/MachO/RelocationObject.hpp>
#include <LIEF/MachO/RelocationDyld.hpp>
#include <LIEF/MachO/RelocationFixup.hpp>
#include <LIEF/MachO/BindingInfo.hpp>
#include <LIEF/MachO/DyldBindingInfo.hpp>
#include <LIEF/MachO/ExportInfo.hpp>
#include <LIEF/MachO/FunctionStarts.hpp>
#include <LIEF/MachO/CodeSignature.hpp>
#include <LIEF/MachO/CodeSignatureDir.hpp>
#include <LIEF/MachO/DataInCode.hpp>
#include <LIEF/MachO/DataCodeEntry.hpp>
#include <LIEF/MachO/SourceVersion.hpp>
#include <LIEF/MachO/VersionMin.hpp>
#include <LIEF/MachO/SegmentSplitInfo.hpp>
#include <LIEF/MachO/SubFramework.hpp>
#include <LIEF/MachO/DyldEnvironment.hpp>
#include <LIEF/MachO/EncryptionInfo.hpp>
#include <LIEF/MachO/BuildVersion.hpp>
#include <LIEF/MachO/FilesetCommand.hpp>
#include <LIEF/MachO/ChainedBindingInfo.hpp>
#include <LIEF/MachO/UnknownCommand.hpp>
#include <LIEF/MachO/TwoLevelHints.hpp>
#include <LIEF/MachO/LinkerOptHint.hpp>
#include <LIEF/MachO/Builder.hpp>

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::MachO::py {

void init_objects(nb::module_& m) {
  CREATE(ParserConfig, m);
  CREATE(Parser, m);

  CREATE(FatBinary, m);
  CREATE(Binary, m);
  CREATE(Header, m);
  CREATE(LoadCommand, m);
  CREATE(UUIDCommand, m);
  CREATE(SymbolCommand, m);
  CREATE(SegmentCommand, m);
  CREATE(Section, m);
  CREATE(MainCommand, m);
  CREATE(DynamicSymbolCommand, m);
  CREATE(DylinkerCommand, m);
  CREATE(DyldInfo, m);
  CREATE(DyldChainedFixups, m);
  CREATE(DyldExportsTrie, m);
  CREATE(DylibCommand, m);
  CREATE(ThreadCommand, m);
  CREATE(RPathCommand, m);
  CREATE(Symbol, m);
  CREATE(Relocation, m);
  CREATE(RelocationObject, m);
  CREATE(RelocationDyld, m);
  CREATE(RelocationFixup, m);
  CREATE(BindingInfo, m);
  CREATE(DyldBindingInfo, m);
  CREATE(ExportInfo, m);
  CREATE(FunctionStarts, m);
  CREATE(CodeSignature, m);
  CREATE(CodeSignatureDir, m);
  CREATE(DataInCode, m);
  CREATE(DataCodeEntry, m);
  CREATE(SourceVersion, m);
  CREATE(VersionMin, m);
  CREATE(SegmentSplitInfo, m);
  CREATE(SubFramework, m);
  CREATE(DyldEnvironment, m);
  CREATE(EncryptionInfo, m);
  CREATE(BuildVersion, m);
  CREATE(FilesetCommand, m);
  CREATE(ChainedBindingInfo, m);
  CREATE(TwoLevelHints, m);
  CREATE(LinkerOptHint, m);
  CREATE(UnknownCommand, m);
  CREATE(Builder, m);
}

void init(nb::module_& m) {
  nb::module_ macho_mod = m.def_submodule("MachO", "Python API for the MachO format");
  init_enums(macho_mod);
  init_objects(macho_mod);
  init_utils(macho_mod);
}
}
