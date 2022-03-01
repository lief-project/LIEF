/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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

namespace LIEF {
namespace PE {

void init_python_module(py::module& m) {
  py::module LIEF_PE_module = m.def_submodule("PE", "Python API for the LIEF's PE format");

  init_enums(LIEF_PE_module);
  init_objects(LIEF_PE_module);
  init_utils(LIEF_PE_module);

 LIEF_PE_module.def("oid_to_string",
      &oid_to_string,
      "Convert an OID to a human-readable string");


  // Opaque containers
  py::bind_vector<std::vector<LangCodeItem>>(m, "ListLangCodeItem");
  py::bind_map<dict_langcode_item>(m, "DictStringVersion");
}

void init_objects(py::module& m) {
  CREATE(Parser, m);

  CREATE(DosHeader, m);
  CREATE(Header, m);
  CREATE(OptionalHeader, m);
  CREATE(RichHeader, m);
  CREATE(RichEntry, m);
  CREATE(DataDirectory, m);
  CREATE(Section, m);
  CREATE(Relocation, m);
  CREATE(RelocationEntry, m);
  CREATE(Export, m);
  CREATE(ExportEntry, m);
  CREATE(TLS, m);
  CREATE(Symbol, m);
  CREATE(Debug, m);
  CREATE(CodeView, m);
  CREATE(CodeViewPDB, m);
  CREATE(Pogo, m);
  CREATE(PogoEntry, m);
  CREATE(Import, m);
  CREATE(ImportEntry, m);
  CREATE(DelayImport, m);
  CREATE(DelayImportEntry, m);
  CREATE(ResourcesManager, m);
  CREATE(ResourceNode, m);
  CREATE(ResourceData, m);
  CREATE(ResourceDirectory, m);
  CREATE(ResourceVersion, m);
  CREATE(ResourceStringFileInfo, m);
  CREATE(ResourceFixedFileInfo, m);
  CREATE(ResourceVarFileInfo, m);
  CREATE(LangCodeItem, m);
  CREATE(ResourceIcon, m);
  CREATE(ResourceDialog, m);
  CREATE(ResourceDialogItem, m);
  CREATE(ResourceStringTable, m);
  CREATE(ResourceAccelerator, m);
  CREATE(Signature, m);
  CREATE(RsaInfo, m);
  CREATE(x509, m);
  CREATE(ContentInfo, m);
  CREATE(SignerInfo, m);
  CREATE(CodeIntegrity, m);
  CREATE(Attribute, m);
  CREATE(ContentType, m);
  CREATE(GenericType, m);
  CREATE(MsSpcNestedSignature, m);
  CREATE(MsSpcStatementType, m);
  CREATE(PKCS9AtSequenceNumber, m);
  CREATE(PKCS9CounterSignature, m);
  CREATE(PKCS9MessageDigest, m);
  CREATE(PKCS9SigningTime, m);
  CREATE(SpcSpOpusInfo, m);

  CREATE(LoadConfiguration, m);
  CREATE(LoadConfigurationV0, m);
  CREATE(LoadConfigurationV1, m);
  CREATE(LoadConfigurationV2, m);
  CREATE(LoadConfigurationV3, m);
  CREATE(LoadConfigurationV4, m);
  CREATE(LoadConfigurationV5, m);
  CREATE(LoadConfigurationV6, m);
  CREATE(LoadConfigurationV7, m);

  CREATE(Binary, m);
  CREATE(Builder, m);

}


}
}
