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
#include "LIEF/PE/signature/OIDToString.hpp"

#include "pyPE.hpp"

//
// PE modules
//
void init_PE_module(py::module& m) {
  py::module LIEF_PE_module = m.def_submodule("PE", "Python API for PE");

 LIEF_PE_module.def("oid_to_string",
      &oid_to_string,
      "Convert an OID to a human-readable string");


  // Enums
  init_PE_Structures_enum(LIEF_PE_module);

  // utils
  init_PE_utils(LIEF_PE_module);

  // Objects
  init_PE_Parser_class(LIEF_PE_module);
  init_PE_Binary_class(LIEF_PE_module);
  init_PE_DataDirectory_class(LIEF_PE_module);
  init_PE_Header_class(LIEF_PE_module);
  init_PE_DosHeader_class(LIEF_PE_module);
  init_PE_RichHeader_class(LIEF_PE_module);
  init_PE_RichEntry_class(LIEF_PE_module);
  init_PE_OptionalHeader_class(LIEF_PE_module);
  init_PE_Section_class(LIEF_PE_module);
  init_PE_Import_class(LIEF_PE_module);
  init_PE_ImportEntry_class(LIEF_PE_module);
  init_PE_TLS_class(LIEF_PE_module);
  init_PE_Symbol_class(LIEF_PE_module);
  init_PE_Relocation_class(LIEF_PE_module);
  init_PE_RelocationEntry_class(LIEF_PE_module);
  init_PE_Export_class(LIEF_PE_module);
  init_PE_ExportEntry_class(LIEF_PE_module);
  init_PE_Builder_class(LIEF_PE_module);
  init_PE_Debug_class(LIEF_PE_module);
  init_PE_CodeView_class(LIEF_PE_module);
  init_PE_CodeViewPDB_class(LIEF_PE_module);
  init_PE_CodeIntegrity_class(LIEF_PE_module);
  init_PE_load_configurations(LIEF_PE_module);

  init_PE_Signature_class(LIEF_PE_module);
  init_PE_ContentInfo_class(LIEF_PE_module);
  init_PE_x509_class(LIEF_PE_module);
  init_PE_SignerInfo_class(LIEF_PE_module);
  init_PE_AuthenticatedAttributes_class(LIEF_PE_module);

  init_PE_ResourceNode_class(LIEF_PE_module);
  init_PE_ResourceData_class(LIEF_PE_module);
  init_PE_ResourceDirectory_class(LIEF_PE_module);

  init_PE_ResourcesIcon_class(LIEF_PE_module);

  init_PE_ResourceVersion_class(LIEF_PE_module);
  init_PE_ResourceFixedFileInfo_class(LIEF_PE_module);
  init_PE_ResourceVarFileInfo_class(LIEF_PE_module);
  init_PE_ResourceStringFileInfo_class(LIEF_PE_module);
  init_PE_LangCodeItem_class(LIEF_PE_module);

  init_PE_ResourcesDialog_class(LIEF_PE_module);
  init_PE_ResourcesDialogItem_class(LIEF_PE_module);

  init_PE_ResourcesManager_class(LIEF_PE_module);

  // Opaque containers
  py::bind_vector<std::vector<LangCodeItem>>(m, "ListLangCodeItem");
  py::bind_map<dict_langcode_item>(m, "DictStringVersion");
}
