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
#ifndef PY_LIEF_MACHO_H_
#define PY_LIEF_MACHO_H_

#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Builder.hpp"
#include "LIEF/MachO/Parser.hpp"
#include "pyLIEF.hpp"

#define SPECIALIZE_CREATE(X) \
  template <>                \
  void create<X>(py::module&)

#define CREATE(X, Y) create<X>(Y)

namespace LIEF {
namespace MachO {

template <class T>
void create(py::module&);

void init_python_module(py::module& m);
void init_objects(py::module&);
void init_enums(py::module&);
void init_utils(py::module&);

SPECIALIZE_CREATE(Parser);
SPECIALIZE_CREATE(ParserConfig);

SPECIALIZE_CREATE(FatBinary);
SPECIALIZE_CREATE(Binary);
SPECIALIZE_CREATE(Header);
SPECIALIZE_CREATE(LoadCommand);
SPECIALIZE_CREATE(UUIDCommand);
SPECIALIZE_CREATE(SymbolCommand);
SPECIALIZE_CREATE(SegmentCommand);
SPECIALIZE_CREATE(Section);
SPECIALIZE_CREATE(MainCommand);
SPECIALIZE_CREATE(DynamicSymbolCommand);
SPECIALIZE_CREATE(DylinkerCommand);
SPECIALIZE_CREATE(DyldInfo);
SPECIALIZE_CREATE(DylibCommand);
SPECIALIZE_CREATE(ThreadCommand);
SPECIALIZE_CREATE(RPathCommand);
SPECIALIZE_CREATE(Symbol);
SPECIALIZE_CREATE(Relocation);
SPECIALIZE_CREATE(RelocationObject);
SPECIALIZE_CREATE(RelocationDyld);
SPECIALIZE_CREATE(BindingInfo);
SPECIALIZE_CREATE(ExportInfo);
SPECIALIZE_CREATE(FunctionStarts);
SPECIALIZE_CREATE(CodeSignature);
SPECIALIZE_CREATE(DataInCode);
SPECIALIZE_CREATE(DataCodeEntry);
SPECIALIZE_CREATE(SourceVersion);
SPECIALIZE_CREATE(VersionMin);
SPECIALIZE_CREATE(SegmentSplitInfo);
SPECIALIZE_CREATE(SubFramework);
SPECIALIZE_CREATE(DyldEnvironment);
SPECIALIZE_CREATE(EncryptionInfo);
SPECIALIZE_CREATE(BuildVersion);
SPECIALIZE_CREATE(FilesetCommand);

}  // namespace MachO
}  // namespace LIEF

// Opaque containers
PYBIND11_MAKE_OPAQUE(std::vector<LIEF::MachO::Binary*>)

#endif
