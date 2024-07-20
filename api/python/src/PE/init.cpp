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
#include "PE/init.hpp"
#include "PE/enums.hpp"
#include "PE/pyPE.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/CodeIntegrity.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/ParserConfig.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/RichHeader.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/debug/CodeView.hpp"
#include "LIEF/PE/debug/Repro.hpp"
#include "LIEF/PE/debug/CodeViewPDB.hpp"
#include "LIEF/PE/debug/Pogo.hpp"
#include "LIEF/PE/debug/PogoEntry.hpp"
#include "LIEF/PE/resources/LangCodeItem.hpp"
#include "LIEF/PE/resources/langs.hpp"
#include "LIEF/PE/signature/attributes.hpp"
#include "LIEF/PE/signature/PKCS9TSTInfo.hpp"
#include "LIEF/PE/signature/SpcIndirectData.hpp"
#include "LIEF/PE/signature/GenericContent.hpp"

#define CREATE(X,Y) create<X>(Y)

namespace LIEF::PE::py {

void init_resources(nb::module_& m) {
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
  CREATE(RESOURCE_LANGS, m);
}

void init_load_configs(nb::module_& m) {
  CREATE(LoadConfiguration, m);
  CREATE(LoadConfigurationV0, m);
  CREATE(LoadConfigurationV1, m);
  CREATE(LoadConfigurationV2, m);
  CREATE(LoadConfigurationV3, m);
  CREATE(LoadConfigurationV4, m);
  CREATE(LoadConfigurationV5, m);
  CREATE(LoadConfigurationV6, m);
  CREATE(LoadConfigurationV7, m);
  CREATE(LoadConfigurationV8, m);
  CREATE(LoadConfigurationV9, m);
  CREATE(LoadConfigurationV10, m);
  CREATE(LoadConfigurationV11, m);
}


void init_debug(nb::module_& m) {
  CREATE(Debug, m);
  CREATE(CodeView, m);
  CREATE(CodeViewPDB, m);
  CREATE(Repro, m);
  CREATE(Pogo, m);
  CREATE(PogoEntry, m);
}

void init_signature(nb::module_& m) {
  CREATE(Signature, m);
  CREATE(RsaInfo, m);
  CREATE(x509, m);
  CREATE(ContentInfo, m);
  CREATE(GenericContent, m);
  CREATE(SpcIndirectData, m);
  CREATE(SignerInfo, m);
  CREATE(CodeIntegrity, m);
  CREATE(Attribute, m);
  CREATE(ContentType, m);
  CREATE(GenericType, m);
  CREATE(MsSpcNestedSignature, m);
  CREATE(MsSpcStatementType, m);
  CREATE(MsManifestBinaryID, m);
  CREATE(PKCS9AtSequenceNumber, m);
  CREATE(PKCS9CounterSignature, m);
  CREATE(PKCS9MessageDigest, m);
  CREATE(PKCS9SigningTime, m);
  CREATE(SpcSpOpusInfo, m);
  CREATE(MsCounterSign, m);
  CREATE(SpcRelaxedPeMarkerCheck, m);
  CREATE(SigningCertificateV2, m);
  CREATE(PKCS9TSTInfo, m);
}

void init_objects(nb::module_& m) {
  CREATE(ParserConfig, m);
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
  CREATE(Import, m);
  CREATE(ImportEntry, m);
  CREATE(DelayImport, m);
  CREATE(DelayImportEntry, m);
  {
    init_debug(m);
    init_resources(m);
    init_signature(m);
    init_load_configs(m);
  }
  CREATE(Binary, m);
  CREATE(Builder, m);
}

void init(nb::module_& m) {
  nb::module_ pe_mod = m.def_submodule("PE", "Python API for the PE format");
  init_enums(pe_mod);
  init_objects(pe_mod);
  init_utils(pe_mod);
}
}
