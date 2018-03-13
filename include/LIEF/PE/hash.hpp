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
#ifndef LIEF_PE_HASH_H_
#define LIEF_PE_HASH_H_

#include "LIEF/visibility.h"
#include "LIEF/hash.hpp"
#include "LIEF/PE.hpp"
#include "LIEF/Abstract/hash.hpp"

namespace LIEF {
namespace PE {

class LIEF_API Hash : public LIEF::Hash {
  public:
  static size_t hash(const Object& obj);

  public:
  using LIEF::Hash::Hash;
  using LIEF::Hash::hash;
  using LIEF::Hash::visit;

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
  virtual void visit(const LangCodeItem& resource_lci)            override;
  virtual void visit(const ResourceIcon& resource_icon)           override;
  virtual void visit(const ResourceDialog& dialog)                override;
  virtual void visit(const ResourceDialogItem& dialog_item)       override;
  virtual void visit(const Signature& signature)                  override;
  virtual void visit(const x509& x509)                            override;
  virtual void visit(const SignerInfo& signerinfo)                override;
  //virtual void visit(const ContentInfo& contentinfo)              override;
  virtual void visit(const AuthenticatedAttributes& auth)         override;
  virtual void visit(const CodeIntegrity& code_integrity)         override;

  virtual void visit(const LoadConfiguration& config)    override;
  virtual void visit(const LoadConfigurationV0& config)  override;
  virtual void visit(const LoadConfigurationV1& config)  override;
  virtual void visit(const LoadConfigurationV2& config)  override;
  virtual void visit(const LoadConfigurationV3& config)  override;
  virtual void visit(const LoadConfigurationV4& config)  override;
  virtual void visit(const LoadConfigurationV5& config)  override;
  virtual void visit(const LoadConfigurationV6& config)  override;
  virtual void visit(const LoadConfigurationV7& config)  override;

  virtual ~Hash(void);
};

}
}

#endif
