/* Copyright 2024 - 2025 R. Thomas
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
#pragma once
#include "LIEF/rust/PE/Binary.hpp"
#include "LIEF/rust/PE/Symbol.hpp"
#include "LIEF/rust/PE/COFFString.hpp"
#include "LIEF/rust/PE/CodeIntegrity.hpp"
#include "LIEF/rust/PE/DataDirectories.hpp"
#include "LIEF/rust/PE/DelayImport.hpp"
#include "LIEF/rust/PE/DelayImportEntry.hpp"
#include "LIEF/rust/PE/DosHeader.hpp"
#include "LIEF/rust/PE/Export.hpp"
#include "LIEF/rust/PE/ExportEntry.hpp"
#include "LIEF/rust/PE/Header.hpp"
#include "LIEF/rust/PE/Import.hpp"
#include "LIEF/rust/PE/ImportEntry.hpp"
#include "LIEF/rust/PE/OptionalHeader.hpp"
#include "LIEF/rust/PE/Relocation.hpp"
#include "LIEF/rust/PE/RelocationEntry.hpp"
#include "LIEF/rust/PE/ResourceData.hpp"
#include "LIEF/rust/PE/ResourceDirectory.hpp"
#include "LIEF/rust/PE/ResourceNode.hpp"
#include "LIEF/rust/PE/ResourcesManager.hpp"
#include "LIEF/rust/PE/RichEntry.hpp"
#include "LIEF/rust/PE/RichHeader.hpp"
#include "LIEF/rust/PE/Section.hpp"
#include "LIEF/rust/PE/TLS.hpp"
#include "LIEF/rust/PE/AuxiliarySymbol.hpp"
#include "LIEF/rust/PE/utils.hpp"

#include "LIEF/rust/PE/AuxiliarySymbols/AuxiliaryCLRToken.hpp"
#include "LIEF/rust/PE/AuxiliarySymbols/AuxiliaryFile.hpp"
#include "LIEF/rust/PE/AuxiliarySymbols/AuxiliaryFunctionDefinition.hpp"
#include "LIEF/rust/PE/AuxiliarySymbols/AuxiliaryWeakExternal.hpp"
#include "LIEF/rust/PE/AuxiliarySymbols/AuxiliarybfAndefSymbol.hpp"
#include "LIEF/rust/PE/AuxiliarySymbols/AuxiliarySectionDefinition.hpp"

#include "LIEF/rust/PE/debug/Debug.hpp"
#include "LIEF/rust/PE/debug/CodeView.hpp"
#include "LIEF/rust/PE/debug/CodeViewPDB.hpp"
#include "LIEF/rust/PE/debug/Pogo.hpp"
#include "LIEF/rust/PE/debug/PogoEntry.hpp"
#include "LIEF/rust/PE/debug/Repro.hpp"
#include "LIEF/rust/PE/debug/PDBChecksum.hpp"
#include "LIEF/rust/PE/debug/VCFeature.hpp"
#include "LIEF/rust/PE/debug/ExDllCharacteristics.hpp"
#include "LIEF/rust/PE/debug/FPO.hpp"

#include "LIEF/rust/PE/ExceptionInfo.hpp"
#include "LIEF/rust/PE/RuntimeFunctionX64.hpp"
#include "LIEF/rust/PE/RuntimeFunctionAArch64.hpp"
#include "LIEF/rust/PE/UnwindCodeX64.hpp"

#include "LIEF/rust/PE/signature/Signature.hpp"
#include "LIEF/rust/PE/signature/SpcIndirectData.hpp"
#include "LIEF/rust/PE/signature/PKCS9TSTInfo.hpp"
#include "LIEF/rust/PE/signature/GenericContent.hpp"
#include "LIEF/rust/PE/signature/ContentInfo.hpp"
#include "LIEF/rust/PE/signature/x509.hpp"
#include "LIEF/rust/PE/signature/RsaInfo.hpp"
#include "LIEF/rust/PE/signature/SignerInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"
#include "LIEF/rust/PE/signature/attributes/ContentType.hpp"
#include "LIEF/rust/PE/signature/attributes/GenericType.hpp"
#include "LIEF/rust/PE/signature/attributes/MsSpcNestedSignature.hpp"
#include "LIEF/rust/PE/signature/attributes/MsSpcStatementType.hpp"
#include "LIEF/rust/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"
#include "LIEF/rust/PE/signature/attributes/PKCS9CounterSignature.hpp"
#include "LIEF/rust/PE/signature/attributes/PKCS9MessageDigest.hpp"
#include "LIEF/rust/PE/signature/attributes/PKCS9SigningTime.hpp"
#include "LIEF/rust/PE/signature/attributes/SpcSpOpusInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/MsCounterSign.hpp"
#include "LIEF/rust/PE/signature/attributes/MsManifestBinaryID.hpp"
#include "LIEF/rust/PE/signature/attributes/SpcRelaxedPeMarkerCheck.hpp"
#include "LIEF/rust/PE/signature/attributes/SigningCertificateV2.hpp"

#include "LIEF/rust/PE/LoadConfiguration/LoadConfiguration.hpp"
#include "LIEF/rust/PE/LoadConfiguration/CHPEMetadata.hpp"
#include "LIEF/rust/PE/LoadConfiguration/VolatileMetadata.hpp"
#include "LIEF/rust/PE/LoadConfiguration/EnclaveConfiguration.hpp"
#include "LIEF/rust/PE/LoadConfiguration/DynamicRelocation/DynamicRelocation.hpp"
#include "LIEF/rust/PE/LoadConfiguration/DynamicRelocation/DynamicFixup.hpp"

