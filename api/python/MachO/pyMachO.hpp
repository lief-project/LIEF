/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Builder.hpp"

#include "pyLIEF.hpp"

using namespace LIEF::MachO;

PYBIND11_MAKE_OPAQUE(std::vector<Binary*>)

void init_MachO_ParserConfig_class(py::module&);
void init_MachO_Parser_class(py::module&);
void init_MachO_FatBinary_class(py::module&);
void init_MachO_Binary_class(py::module&);
void init_MachO_Header_class(py::module&);
void init_MachO_LoadCommand_class(py::module&);
void init_MachO_DylibCommand_class(py::module&);
void init_MachO_SegmentCommand_class(py::module&);
void init_MachO_Section_class(py::module&);
void init_MachO_Symbol_class(py::module&);
void init_MachO_SymbolCommand_class(py::module&);
void init_MachO_UUIDCommand_class(py::module&);
void init_MachO_MainCommand_class(py::module&);
void init_MachO_DylinkerCommand_class(py::module&);
void init_MachO_DyldInfo_class(py::module&);
void init_MachO_FunctionStarts_class(py::module&);
void init_MachO_SourceVersion_class(py::module&);
void init_MachO_VersionMin_class(py::module&);
void init_MachO_Relocation_class(py::module&);
void init_MachO_RelocationObject_class(py::module&);
void init_MachO_RelocationDyld_class(py::module&);
void init_MachO_BindingInfo_class(py::module&);
void init_MachO_ExportInfo_class(py::module&);
void init_MachO_ThreadCommand_class(py::module&);
void init_MachO_RPathCommand_class(py::module&);
void init_MachO_DynamicSymbolCommand_class(py::module&);
void init_MachO_CodeSignature_class(py::module&);
void init_MachO_DataInCode_class(py::module&);
void init_MachO_DataCodeEntry_class(py::module&);
void init_MachO_SegmentSplitInfo_class(py::module&);
void init_MachO_SubFramework_class(py::module&);
void init_MachO_DyldEnvironment_class(py::module&);

// Enums
void init_MachO_Structures_enum(py::module&);


#endif
