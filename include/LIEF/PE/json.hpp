/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
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
#ifndef LIEF_PE_VISITOR_JSONS_H_
#define LIEF_PE_VISITOR_JSONS_H_

#include "LIEF/visibility.h"
#include "LIEF/visitors/json.hpp"

namespace LIEF {

class Binary;
class Symbol;
class Section;

namespace PE {

class Binary;
class DosHeader;
class RichHeader;
class RichEntry;
class Header;
class OptionalHeader;
class DataDirectory;
class Section;
class Relocation;
class RelocationEntry;
class Export;
class ExportEntry;
class TLS;
class Symbol;
class Debug;
class CodeView;
class CodeViewPDB;
class Import;
class ImportEntry;
class ResourceNode;
class ResourceData;
class ResourceDirectory;
class ResourcesManager;
class ResourceVersion;
class ResourceStringFileInfo;
class ResourceFixedFileInfo;
class ResourceVarFileInfo;
class ResourceStringTable;
class ResourceAccelerator;
class LangCodeItem;
class ResourceIcon;
class ResourceDialog;
class ResourceDialogItem;
class Signature;
class x509;
class SignerInfo;
class ContentInfo;
class Attribute;
class ContentType;
class GenericType;
//class MsCounterSign;
class MsSpcNestedSignature;
class MsSpcStatementType;
class PKCS9AtSequenceNumber;
class PKCS9CounterSignature;
class PKCS9MessageDigest;
class PKCS9SigningTime;
class SpcSpOpusInfo;
class CodeIntegrity;
class LoadConfiguration;
class LoadConfigurationV0;
class LoadConfigurationV1;
class LoadConfigurationV2;
class LoadConfigurationV3;
class LoadConfigurationV4;
class LoadConfigurationV5;
class LoadConfigurationV6;
class LoadConfigurationV7;
class Pogo;
class PogoEntry;

LIEF_API json to_json(const Object& v);
LIEF_API std::string to_json_str(const Object& v);

class LIEF_API JsonVisitor : public LIEF::JsonVisitor {
  public:
  using LIEF::JsonVisitor::JsonVisitor;

  public:
  virtual void visit(const Binary& Binary)                        override;
  virtual void visit(const DosHeader& dos_header)                 override;
  virtual void visit(const RichHeader& rich_header)               override;
  virtual void visit(const RichEntry& rich_entry)                 override;
  virtual void visit(const Header& header)                        override;
  virtual void visit(const OptionalHeader& optional_header)       override;
  virtual void visit(const DataDirectory& data_directory)         override;
  virtual void visit(const Section& section)                      override;
  virtual void visit(const Relocation& relocation)                override;
  virtual void visit(const RelocationEntry& relocation_entry)     override;
  virtual void visit(const Export& export_)                       override;
  virtual void visit(const ExportEntry& export_entry)             override;
  virtual void visit(const TLS& tls)                              override;
  virtual void visit(const Symbol& Symbol)                        override;
  virtual void visit(const Debug& debug)                          override;
  virtual void visit(const CodeView& dv)                          override;
  virtual void visit(const CodeViewPDB& cvpdb)                    override;
  virtual void visit(const Import& import)                        override;
  virtual void visit(const ImportEntry& import_entry)             override;
  virtual void visit(const ResourceNode& resource_node)           override;
  virtual void visit(const ResourceData& resource_data)           override;
  virtual void visit(const ResourceDirectory& resource_directory) override;
  virtual void visit(const ResourcesManager& resources_manager)   override;
  virtual void visit(const ResourceVersion& resource_version)     override;
  virtual void visit(const ResourceStringFileInfo& resource_sfi)  override;
  virtual void visit(const ResourceFixedFileInfo& resource_ffi)   override;
  virtual void visit(const ResourceVarFileInfo& resource_vfi)     override;
  virtual void visit(const ResourceStringTable& resource_st)      override;
  virtual void visit(const ResourceAccelerator& resource_acc)     override;
  virtual void visit(const LangCodeItem& resource_lci)            override;
  virtual void visit(const ResourceIcon& resource_icon)           override;
  virtual void visit(const ResourceDialog& dialog)                override;
  virtual void visit(const ResourceDialogItem& dialog_item)       override;
  virtual void visit(const Signature& signature)                  override;
  virtual void visit(const x509& x509)                            override;
  virtual void visit(const SignerInfo& signerinfo)                override;
  virtual void visit(const ContentInfo& contentinfo)              override;
  virtual void visit(const Attribute& attr)                       override;
  virtual void visit(const ContentType& attr)                     override;
  virtual void visit(const GenericType& attr)                     override;
  //virtual void visit(const MsCounterSign& attr)                 override;
  virtual void visit(const MsSpcNestedSignature& attr)            override;
  virtual void visit(const MsSpcStatementType& attr)              override;
  virtual void visit(const PKCS9AtSequenceNumber& attr)           override;
  virtual void visit(const PKCS9CounterSignature& attr)           override;
  virtual void visit(const PKCS9MessageDigest& attr)              override;
  virtual void visit(const PKCS9SigningTime& attr)                override;
  virtual void visit(const SpcSpOpusInfo& attr)                   override;
  virtual void visit(const CodeIntegrity& code_integrity)         override;
  virtual void visit(const LoadConfiguration& config)             override;
  virtual void visit(const LoadConfigurationV0& config)           override;
  virtual void visit(const LoadConfigurationV1& config)           override;
  virtual void visit(const LoadConfigurationV2& config)           override;
  virtual void visit(const LoadConfigurationV3& config)           override;
  virtual void visit(const LoadConfigurationV4& config)           override;
  virtual void visit(const LoadConfigurationV5& config)           override;
  virtual void visit(const LoadConfigurationV6& config)           override;
  virtual void visit(const LoadConfigurationV7& config)           override;

  virtual void visit(const Pogo& pogo)        override;
  virtual void visit(const PogoEntry& entry)  override;


  virtual void visit(const LIEF::Binary& binary)   override;
  virtual void visit(const LIEF::Symbol& symbol)   override;
  virtual void visit(const LIEF::Section& section) override;
};

}
}

#endif
