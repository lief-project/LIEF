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
#ifndef PY_LIEF_PE_H_
#define PY_LIEF_PE_H_

#include <pybind11/stl_bind.h>
#include <map>
#include <string>

#include "LIEF/PE.hpp"

#include "pyLIEF.hpp"

using namespace LIEF::PE;

// utils
void init_PE_utils(py::module&);

void init_PE_Parser_class(py::module&);
void init_PE_Binary_class(py::module&);
void init_PE_DataDirectory_class(py::module&);
void init_PE_Header_class(py::module&);
void init_PE_DosHeader_class(py::module&);
void init_PE_RichHeader_class(py::module&);
void init_PE_RichEntry_class(py::module&);
void init_PE_Section_class(py::module&);
void init_PE_OptionalHeader_class(py::module&);
void init_PE_Import_class(py::module&);
void init_PE_ImportEntry_class(py::module&);
void init_PE_TLS_class(py::module&);
void init_PE_Symbol_class(py::module&);
void init_PE_Relocation_class(py::module&);
void init_PE_RelocationEntry_class(py::module&);
void init_PE_Export_class(py::module&);
void init_PE_ExportEntry_class(py::module&);
void init_PE_Builder_class(py::module&);
void init_PE_Debug_class(py::module&);
void init_PE_CodeView_class(py::module&);
void init_PE_CodeViewPDB_class(py::module&);
void init_PE_CodeIntegrity_class(py::module&);
void init_PE_load_configurations(py::module&);

void init_PE_Signature_class(py::module&);
void init_PE_ContentInfo_class(py::module&);
void init_PE_x509_class(py::module&);
void init_PE_SignerInfo_class(py::module&);
void init_PE_AuthenticatedAttributes_class(py::module&);

void init_PE_ResourceNode_class(py::module&);
void init_PE_ResourceData_class(py::module&);
void init_PE_ResourceDirectory_class(py::module&);

void init_PE_ResourcesIcon_class(py::module&);

void init_PE_ResourceVersion_class(py::module&);
void init_PE_ResourceFixedFileInfo_class(py::module&);
void init_PE_ResourceVarFileInfo_class(py::module&);
void init_PE_ResourceStringFileInfo_class(py::module&);
void init_PE_LangCodeItem_class(py::module&);

void init_PE_ResourcesDialog_class(py::module&);
void init_PE_ResourcesDialogItem_class(py::module&);

void init_PE_ResourcesManager_class(py::module&);

// Enums
void init_PE_Structures_enum(py::module&);


// Load Configurations
void init_PE_LoadConfiguration_class(py::module&);
void init_PE_LoadConfigurationV0_class(py::module&);
void init_PE_LoadConfigurationV1_class(py::module&);
void init_PE_LoadConfigurationV2_class(py::module&);
void init_PE_LoadConfigurationV3_class(py::module&);
void init_PE_LoadConfigurationV4_class(py::module&);
void init_PE_LoadConfigurationV5_class(py::module&);
void init_PE_LoadConfigurationV6_class(py::module&);
void init_PE_LoadConfigurationV7_class(py::module&);


// Opaque containers
PYBIND11_MAKE_OPAQUE(std::vector<LangCodeItem>)
using dict_langcode_item = std::map<std::u16string, std::u16string>;
PYBIND11_MAKE_OPAQUE(dict_langcode_item)

#endif
