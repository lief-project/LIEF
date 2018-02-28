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
#ifndef PY_LIEF_ELF_H_
#define PY_LIEF_ELF_H_

#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"

#include "pyLIEF.hpp"
using namespace LIEF::ELF;

void init_ELF_Parser_class(py::module&);
void init_ELF_Binary_class(py::module&);
void init_ELF_Header_class(py::module&);
void init_ELF_Section_class(py::module&);
void init_ELF_Segment_class(py::module&);
void init_ELF_Symbol_class(py::module&);
void init_ELF_Relocation_class(py::module&);
void init_ELF_SymbolVersion_class(py::module&);
void init_ELF_SymbolVersionAux_class(py::module&);
void init_ELF_SymbolVersionRequirement_class(py::module&);
void init_ELF_SymbolVersionDefinition_class(py::module&);
void init_ELF_SymbolVersionAuxRequirement_class(py::module&);
void init_ELF_DynamicEntry_class(py::module&);
void init_ELF_DynamicEntryLibrary_class(py::module&);
void init_ELF_DynamicSharedObject_class(py::module&);
void init_ELF_DynamicEntryArray_class(py::module&);
void init_ELF_DynamicEntryRpath_class(py::module&);
void init_ELF_DynamicEntryRunPath_class(py::module&);
void init_ELF_DynamicEntryFlags_class(py::module&);
void init_ELF_GnuHash_class(py::module&);
void init_ELF_SysvHash_class(py::module&);
void init_ELF_Builder_class(py::module&);
void init_ELF_Note_class(py::module&);
void init_ELF_AndroidNote_class(py::module&);

// Enums
void init_ELF_Structures_enum(py::module&);

void init_ELF32_sizes(py::module&);
void init_ELF64_sizes(py::module&);



#endif
