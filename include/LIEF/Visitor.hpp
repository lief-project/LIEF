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
#ifndef LIEF_VISITOR_H_
#define LIEF_VISITOR_H_
#include <set>
#include <vector>
#include <array>
#include <string>
#include <functional>
#include <iostream>
#include <utility>

#include "LIEF/config.h"

#include "LIEF/visibility.h"

#include "LIEF/PE/signature/types.hpp"

#include "LIEF/visitor_macros.hpp"


namespace LIEF {
// Forward declarations
// ====================
class Object;
LIEF_ABSTRACT_FORWARD(Binary)
LIEF_ABSTRACT_FORWARD(Header)
LIEF_ABSTRACT_FORWARD(Section)
LIEF_ABSTRACT_FORWARD(Symbol)
LIEF_ABSTRACT_FORWARD(Relocation)

// PE
// ===============================
LIEF_PE_FORWARD(Binary)
LIEF_PE_FORWARD(DosHeader)
LIEF_PE_FORWARD(Header)
LIEF_PE_FORWARD(OptionalHeader)
LIEF_PE_FORWARD(RichHeader)
LIEF_PE_FORWARD(RichEntry)
LIEF_PE_FORWARD(DataDirectory)
LIEF_PE_FORWARD(Section)
LIEF_PE_FORWARD(Relocation)
LIEF_PE_FORWARD(RelocationEntry)
LIEF_PE_FORWARD(Export)
LIEF_PE_FORWARD(ExportEntry)
LIEF_PE_FORWARD(TLS)
LIEF_PE_FORWARD(Symbol)
LIEF_PE_FORWARD(Debug)
LIEF_PE_FORWARD(CodeView)
LIEF_PE_FORWARD(CodeViewPDB)
LIEF_PE_FORWARD(Import)
LIEF_PE_FORWARD(ImportEntry)
LIEF_PE_FORWARD(ResourceNode)
LIEF_PE_FORWARD(ResourceData)
LIEF_PE_FORWARD(ResourceDirectory)
LIEF_PE_FORWARD(ResourcesManager)
LIEF_PE_FORWARD(ResourceVersion)
LIEF_PE_FORWARD(ResourceStringFileInfo)
LIEF_PE_FORWARD(ResourceFixedFileInfo)
LIEF_PE_FORWARD(ResourceVarFileInfo)
LIEF_PE_FORWARD(LangCodeItem)
LIEF_PE_FORWARD(ResourceIcon)
LIEF_PE_FORWARD(ResourceDialog)
LIEF_PE_FORWARD(ResourceDialogItem)
LIEF_PE_FORWARD(Signature)
LIEF_PE_FORWARD(x509)
LIEF_PE_FORWARD(SignerInfo)
LIEF_PE_FORWARD(ContentInfo)
LIEF_PE_FORWARD(AuthenticatedAttributes)
LIEF_PE_FORWARD(CodeIntegrity)
LIEF_PE_FORWARD(LoadConfiguration)
LIEF_PE_FORWARD(LoadConfigurationV0)
LIEF_PE_FORWARD(LoadConfigurationV1)
LIEF_PE_FORWARD(LoadConfigurationV2)
LIEF_PE_FORWARD(LoadConfigurationV3)
LIEF_PE_FORWARD(LoadConfigurationV4)
LIEF_PE_FORWARD(LoadConfigurationV5)
LIEF_PE_FORWARD(LoadConfigurationV6)
LIEF_PE_FORWARD(LoadConfigurationV7)

// ELF
// ==================================
LIEF_ELF_FORWARD(Binary)
LIEF_ELF_FORWARD(Header)
LIEF_ELF_FORWARD(Section)
LIEF_ELF_FORWARD(Segment)
LIEF_ELF_FORWARD(DynamicEntry)
LIEF_ELF_FORWARD(DynamicEntryArray)
LIEF_ELF_FORWARD(DynamicEntryLibrary)
LIEF_ELF_FORWARD(DynamicSharedObject)
LIEF_ELF_FORWARD(DynamicEntryRunPath)
LIEF_ELF_FORWARD(DynamicEntryRpath)
LIEF_ELF_FORWARD(DynamicEntryFlags)
LIEF_ELF_FORWARD(Symbol)
LIEF_ELF_FORWARD(Relocation)
LIEF_ELF_FORWARD(SymbolVersion)
LIEF_ELF_FORWARD(SymbolVersionRequirement)
LIEF_ELF_FORWARD(SymbolVersionDefinition)
LIEF_ELF_FORWARD(SymbolVersionAux)
LIEF_ELF_FORWARD(SymbolVersionAuxRequirement)
LIEF_ELF_FORWARD(Note)
LIEF_ELF_FORWARD(AndroidNote)
LIEF_ELF_FORWARD(GnuHash)
LIEF_ELF_FORWARD(SysvHash)


// MACHO
// ===============================
LIEF_MACHO_FORWARD(Binary)
LIEF_MACHO_FORWARD(Header)
LIEF_MACHO_FORWARD(LoadCommand)
LIEF_MACHO_FORWARD(UUIDCommand)
LIEF_MACHO_FORWARD(SymbolCommand)
LIEF_MACHO_FORWARD(SegmentCommand)
LIEF_MACHO_FORWARD(Section)
LIEF_MACHO_FORWARD(MainCommand)
LIEF_MACHO_FORWARD(DynamicSymbolCommand)
LIEF_MACHO_FORWARD(DylinkerCommand)
LIEF_MACHO_FORWARD(DylibCommand)
LIEF_MACHO_FORWARD(ThreadCommand)
LIEF_MACHO_FORWARD(RPathCommand)
LIEF_MACHO_FORWARD(Symbol)
LIEF_MACHO_FORWARD(Relocation)
LIEF_MACHO_FORWARD(RelocationObject)
LIEF_MACHO_FORWARD(RelocationDyld)
LIEF_MACHO_FORWARD(BindingInfo)
LIEF_MACHO_FORWARD(ExportInfo)


class LIEF_API Visitor {
  public:
  Visitor(void);
  virtual ~Visitor(void);

  virtual void operator()(void);

  template<typename Arg1, typename... Args>
  void operator()(Arg1&& arg1, Args&&... args);

  virtual void visit(const Object&);

  // Abstract Part
  // =============

  //! @brief Method to visit a LIEF::Binary
  LIEF_ABSTRACT_VISITABLE(Binary)

  //! @brief Method to visit a LIEF::Header
  LIEF_ABSTRACT_VISITABLE(Header)

  //! @brief Method to visit a LIEF::Section
  LIEF_ABSTRACT_VISITABLE(Section)

  //! @brief Method to visit a LIEF::Symbol
  LIEF_ABSTRACT_VISITABLE(Symbol)

  //! @brief Method to visit a LIEF::Relocation
  LIEF_ABSTRACT_VISITABLE(Relocation)

  LIEF_ELF_VISITABLE(Binary)
  LIEF_ELF_VISITABLE(Header)
  LIEF_ELF_VISITABLE(Section)
  LIEF_ELF_VISITABLE(Segment)
  LIEF_ELF_VISITABLE(DynamicEntry)
  LIEF_ELF_VISITABLE(DynamicEntryArray)
  LIEF_ELF_VISITABLE(DynamicEntryLibrary)
  LIEF_ELF_VISITABLE(DynamicSharedObject)
  LIEF_ELF_VISITABLE(DynamicEntryRunPath)
  LIEF_ELF_VISITABLE(DynamicEntryRpath)
  LIEF_ELF_VISITABLE(DynamicEntryFlags)
  LIEF_ELF_VISITABLE(Symbol)
  LIEF_ELF_VISITABLE(Relocation)
  LIEF_ELF_VISITABLE(SymbolVersion)
  LIEF_ELF_VISITABLE(SymbolVersionRequirement)
  LIEF_ELF_VISITABLE(SymbolVersionDefinition)
  LIEF_ELF_VISITABLE(SymbolVersionAux)
  LIEF_ELF_VISITABLE(SymbolVersionAuxRequirement)
  LIEF_ELF_VISITABLE(Note)
  LIEF_ELF_VISITABLE(AndroidNote)
  LIEF_ELF_VISITABLE(GnuHash)
  LIEF_ELF_VISITABLE(SysvHash)

  // PE Part
  // =======
  //! @brief Method to visit a LIEF::PE::Binary
  LIEF_PE_VISITABLE(Binary)

  //! @brief Method to visit a LIEF::PE::DosHeader
  LIEF_PE_VISITABLE(DosHeader)

  //! @brief Method to visit a LIEF::PE:RichHeader
  LIEF_PE_VISITABLE(RichHeader)

  //! @brief Method to visit a LIEF::PE:RichEntry
  LIEF_PE_VISITABLE(RichEntry)

  //! @brief Method to visit a LIEF::PE::Header
  LIEF_PE_VISITABLE(Header)

  //! @brief Method to visit a LIEF::PE::OptionalHeader
  LIEF_PE_VISITABLE(OptionalHeader)

  //! @brief Method to visit a LIEF::PE::DataDirectory
  LIEF_PE_VISITABLE(DataDirectory)

  //! @brief Method to visit a LIEF::PE::TLS
  LIEF_PE_VISITABLE(TLS)

  //! @brief Method to visit a LIEF::PE::Symbol
  LIEF_PE_VISITABLE(Symbol)

  //! @brief Method to visit a LIEF::PE::Section
  LIEF_PE_VISITABLE(Section)

  //! @brief Method to visit a LIEF::PE::Relocation
  LIEF_PE_VISITABLE(Relocation)

  //! @brief Method to visit a LIEF::PE::RelocationEntry
  LIEF_PE_VISITABLE(RelocationEntry)

  //! @brief Method to visit a LIEF::PE::Export
  LIEF_PE_VISITABLE(Export)

  //! @brief Method to visit a LIEF::PE::ExportEntry
  LIEF_PE_VISITABLE(ExportEntry)

  //! @brief Method to visit a LIEF::PE::Debug
  LIEF_PE_VISITABLE(Debug)

  //! @brief Method to visit a LIEF::PE::CodeView
  LIEF_PE_VISITABLE(CodeView)

  //! @brief Method to visit a LIEF::PE::CodeViewPDB
  LIEF_PE_VISITABLE(CodeViewPDB)

  //! @brief Method to visit a LIEF::PE::Import
  LIEF_PE_VISITABLE(Import)

  //! @brief Method to visit a LIEF::PE::ImportEntry
  LIEF_PE_VISITABLE(ImportEntry)

  //! @brief Method to visit a LIEF::PE::ResourceNode
  LIEF_PE_VISITABLE(ResourceNode)

  //! @brief Method to visit a LIEF::PE::ResourceData
  LIEF_PE_VISITABLE(ResourceData)

  //! @brief Method to visit a LIEF::PE::ResourceDirectory
  LIEF_PE_VISITABLE(ResourceDirectory)

  //! @brief Method to visit a LIEF::PE::ResourceVersion
  LIEF_PE_VISITABLE(ResourcesManager)

  //! @brief Method to visit a LIEF::PE::ResourceVersion
  LIEF_PE_VISITABLE(ResourceVersion)

  //! @brief Method to visit a LIEF::PE::ResourceStringFileInfo
  LIEF_PE_VISITABLE(ResourceStringFileInfo)

  //! @brief Method to visit a LIEF::PE::ResourceFixedFileInfo
  LIEF_PE_VISITABLE(ResourceFixedFileInfo)

  //! @brief Method to visit a LIEF::PE::ResourceVarFileInfo
  LIEF_PE_VISITABLE(ResourceVarFileInfo)

  //! @brief Method to visit a LIEF::PE::LangCodeItem
  LIEF_PE_VISITABLE(LangCodeItem)

  //! @brief Method to visit a LIEF::PE::ResourceIcon
  LIEF_PE_VISITABLE(ResourceIcon)

  //! @brief Method to visit a LIEF::PE::ResourceDialog
  LIEF_PE_VISITABLE(ResourceDialog)

  //! @brief Method to visit a LIEF::PE::ResourceDialogItem
  LIEF_PE_VISITABLE(ResourceDialogItem)

  //! @brief Method to visit a LIEF::PE::Signature
  LIEF_PE_VISITABLE(Signature)

  //! @brief Method to visit a LIEF::PE::x509
  LIEF_PE_VISITABLE(x509)

  //! @brief Method to visit a LIEF::PE::SignerInfo
  LIEF_PE_VISITABLE(SignerInfo)

  //! @brief Method to visit a LIEF::PE::ContentInfo
  LIEF_PE_VISITABLE(ContentInfo)

  //! @brief Method to visit a LIEF::PE::AuthenticatedAttributes
  LIEF_PE_VISITABLE(AuthenticatedAttributes)

  //! @brief Method to visit a LIEF::PE::issuer_t
  LIEF_PE_VISITABLE(issuer_t)

  //! @brief Method to visit a LIEF::PE::LoadConfiguration
  LIEF_PE_VISITABLE(LoadConfiguration)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV0
  LIEF_PE_VISITABLE(LoadConfigurationV0)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV1
  LIEF_PE_VISITABLE(LoadConfigurationV1)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV2
  LIEF_PE_VISITABLE(LoadConfigurationV2)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV3
  LIEF_PE_VISITABLE(LoadConfigurationV3)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV4
  LIEF_PE_VISITABLE(LoadConfigurationV4)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV5
  LIEF_PE_VISITABLE(LoadConfigurationV5)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV6
  LIEF_PE_VISITABLE(LoadConfigurationV6)

  //! @brief Method to visit a LIEF::PE::LoadConfigurationV7
  LIEF_PE_VISITABLE(LoadConfigurationV7)

  //! @brief Method to visit a LIEF::PE::CodeIntegrity
  LIEF_PE_VISITABLE(CodeIntegrity)

  // MachO part
  // ==========
  //! @brief Method to visit a LIEF::MachO::Binary
  LIEF_MACHO_VISITABLE(Binary)

  //! @brief Method to visit a LIEF::MachO::Header
  LIEF_MACHO_VISITABLE(Header)

  //! @brief Method to visit a LIEF::MachO::LoadCommand
  LIEF_MACHO_VISITABLE(LoadCommand)

  //! @brief Method to visit a LIEF::MachO::UUIDCommand
  LIEF_MACHO_VISITABLE(UUIDCommand)

  //! @brief Method to visit a LIEF::MachO::SymbolCommand
  LIEF_MACHO_VISITABLE(SymbolCommand)

  //! @brief Method to visit a LIEF::MachO::SegmentCommand
  LIEF_MACHO_VISITABLE(SegmentCommand)

  //! @brief Method to visit a LIEF::MachO::Section
  LIEF_MACHO_VISITABLE(Section)

  //! @brief Method to visit a LIEF::MachO::MainCommand
  LIEF_MACHO_VISITABLE(MainCommand)

  //! @brief Method to visit a LIEF::MachO::DynamicSymbolCommand
  LIEF_MACHO_VISITABLE(DynamicSymbolCommand)

  //! @brief Method to visit a LIEF::MachO::DylinkerCommand
  LIEF_MACHO_VISITABLE(DylinkerCommand)

  //! @brief Method to visit a LIEF::MachO::DylibCommand
  LIEF_MACHO_VISITABLE(DylibCommand)

  //! @brief Method to visit a LIEF::MachO::ThreadCommand
  LIEF_MACHO_VISITABLE(ThreadCommand)

  //! @brief Method to visit a LIEF::MachO::RPathCommand
  LIEF_MACHO_VISITABLE(RPathCommand)

  //! @brief Method to visit a LIEF::MachO::Symbol
  LIEF_MACHO_VISITABLE(Symbol)

  //! @brief Method to visit a LIEF::MachO::Relocation
  LIEF_MACHO_VISITABLE(Relocation)

  //! @brief Method to visit a LIEF::MachO::RelocationObject
  LIEF_MACHO_VISITABLE(RelocationObject)

  //! @brief Method to visit a LIEF::MachO::RelocationDyld
  LIEF_MACHO_VISITABLE(RelocationDyld)

  //! @brief Method to visit a LIEF::MachO::BindingInfo
  LIEF_MACHO_VISITABLE(BindingInfo)

  //! @brief Method to visit a LIEF::MachO::ExportInfo
  LIEF_MACHO_VISITABLE(ExportInfo)

  template<class T>
  void dispatch(const T& obj);


  private:
  std::set<size_t> visited_;
};



template<typename Arg1, typename... Args>
void Visitor::operator()(Arg1&& arg1, Args&&... args) {
  this->dispatch(std::forward<Arg1>(arg1));
  this->operator()(std::forward<Args>(args)... );
}

template<class T>
void Visitor::dispatch(const T& obj) {
  size_t hash = reinterpret_cast<size_t>(&obj);
  if (this->visited_.find(hash) != std::end(this->visited_)) {
    // Already visited
    return;
  }

  this->visited_.insert(hash);
  this->visit(obj);
}

}
#endif
