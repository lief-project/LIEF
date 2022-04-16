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
#include <pybind11/stl_bind.h>

#include "pyMachO.hpp"


namespace LIEF {
namespace MachO {

void init_python_module(py::module& m) {
  py::module LIEF_MachO_module = m.def_submodule("MachO", "Python API for the MachO format");

  init_enums(LIEF_MachO_module);
  init_objects(LIEF_MachO_module);
  init_utils(LIEF_MachO_module);
}

void init_objects(py::module& m) {

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
  CREATE(Builder, m);
}

}
}
