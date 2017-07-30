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
#include "LIEF/Visitor.hpp"

#include "LIEF/Abstract/Abstract.hpp"

#include "LIEF/ELF.hpp"
#include "LIEF/PE.hpp"
#include "LIEF/MachO.hpp"

namespace LIEF {
Visitor::Visitor(void) = default;
Visitor::~Visitor(void) = default;


void Visitor::operator()(void) {
}


// visit methods
// =============

// Fundamental types
// =================
void Visitor::visit(size_t) {
}

void Visitor::visit(const std::string&) {
}

void Visitor::visit(const std::u16string&) {
}

void Visitor::visit(const std::vector<uint8_t>&) {
}

// Abstract part
// -------------
void Visitor::visit(const Binary& binary) {
  binary.accept(*this);
}

void Visitor::visit(const Header& header) {
  header.accept(*this);
}

void Visitor::visit(const Section& section) {
  section.accept(*this);
}

void Visitor::visit(const Symbol& symbol) {
  symbol.accept(*this);
}


// ELF part
// --------
void Visitor::visit(const ELF::Binary& binary) {
  binary.accept(*this);
}

void Visitor::visit(const ELF::Header& header) {
  header.accept(*this);
}

void Visitor::visit(const ELF::Section& section) {
  section.accept(*this);
}

void Visitor::visit(const ELF::Segment& segment) {
  segment.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntry& entry) {
  entry.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryArray& array) {
  array.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryLibrary& library) {
  library.accept(*this);
}

void Visitor::visit(const ELF::DynamicSharedObject& shared) {
  shared.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryRunPath& runpath) {
  runpath.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryRpath& rpath) {
  rpath.accept(*this);
}

void Visitor::visit(const ELF::Symbol& symbol) {
  symbol.accept(*this);
}

void Visitor::visit(const ELF::Relocation& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersion& sv) {
  sv.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionRequirement& svr) {
  svr.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionDefinition& svd) {
  svd.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionAux& sva) {
  sva.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionAuxRequirement& svar) {
  svar.accept(*this);
}

void Visitor::visit(const ELF::Note& note) {
  note.accept(*this);
}

void Visitor::visit(const ELF::GnuHash& gnuhash) {
  gnuhash.accept(*this);
}

void Visitor::visit(const ELF::SysvHash& sysvhash) {
  sysvhash.accept(*this);
}

// PE Part
// -------
void Visitor::visit(const PE::Binary& binary) {
  binary.accept(*this);
}

void Visitor::visit(const PE::DosHeader& dos_header) {
  dos_header.accept(*this);
}

void Visitor::visit(const PE::RichHeader& rich_header) {
  rich_header.accept(*this);
}

void Visitor::visit(const PE::RichEntry& rich_entry) {
  rich_entry.accept(*this);
}

void Visitor::visit(const PE::Header& header) {
  header.accept(*this);
}

void Visitor::visit(const PE::OptionalHeader& optional_header) {
  optional_header.accept(*this);
}

void Visitor::visit(const PE::DataDirectory& data_directory) {
  data_directory.accept(*this);
}

void Visitor::visit(const PE::TLS& tls) {
  tls.accept(*this);
}

void Visitor::visit(const PE::Symbol& symbol) {
  symbol.accept(*this);
}

void Visitor::visit(const PE::Section& section) {
  section.accept(*this);
}

void Visitor::visit(const PE::Relocation& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const PE::RelocationEntry& relocation_entry) {
  relocation_entry.accept(*this);
}

void Visitor::visit(const PE::Export& exp) {
  exp.accept(*this);
}

void Visitor::visit(const PE::ExportEntry& export_entry) {
  export_entry.accept(*this);
}

void Visitor::visit(const PE::Debug& debug) {
  debug.accept(*this);
}

void Visitor::visit(const PE::Import& import) {
  import.accept(*this);
}

void Visitor::visit(const PE::ImportEntry& import_entry) {
  import_entry.accept(*this);
}

void Visitor::visit(const PE::ResourceNode& node) {
  node.accept(*this);
}

void Visitor::visit(const PE::ResourceData& data) {
  data.accept(*this);
}

void Visitor::visit(const PE::ResourceDirectory& directory) {
  directory.accept(*this);
}

void Visitor::visit(const PE::ResourcesManager& resources_manager) {
  resources_manager.accept(*this);
}

void Visitor::visit(const PE::ResourceVersion& resource_version) {
  resource_version.accept(*this);
}


void Visitor::visit(const PE::ResourceIcon& resource_icon) {
  resource_icon.accept(*this);
}


void Visitor::visit(const PE::ResourceDialog& resource_dialog) {
  resource_dialog.accept(*this);
}


void Visitor::visit(const PE::ResourceDialogItem& resource_dialogitem) {
  resource_dialogitem.accept(*this);
}


void Visitor::visit(const PE::ResourceStringFileInfo& resource_string_file_info) {
  resource_string_file_info.accept(*this);
}


void Visitor::visit(const PE::ResourceFixedFileInfo& resource_fixed_file_info) {
  resource_fixed_file_info.accept(*this);
}


void Visitor::visit(const PE::ResourceVarFileInfo& resource_var_file_info) {
  resource_var_file_info.accept(*this);
}


void Visitor::visit(const PE::LangCodeItem& lang_code_item) {
  lang_code_item.accept(*this);
}


void Visitor::visit(const PE::Signature& signature) {
  signature.accept(*this);
}

void Visitor::visit(const PE::x509& x509) {
  x509.accept(*this);
}

void Visitor::visit(const PE::SignerInfo& signer_info) {
  signer_info.accept(*this);
}

void Visitor::visit(const PE::ContentInfo& content_info) {
  content_info.accept(*this);
}

void Visitor::visit(const PE::AuthenticatedAttributes& authenticated_attributes) {
  authenticated_attributes.accept(*this);
}

void Visitor::visit(const PE::issuer_t&) {
}

// MachO part
// ----------

void Visitor::visit(const MachO::Binary& binary) {
  binary.accept(*this);
}

void Visitor::visit(const MachO::Header& header) {
  header.accept(*this);
}

void Visitor::visit(const MachO::LoadCommand& load_command) {
  load_command.accept(*this);
}

void Visitor::visit(const MachO::UUIDCommand& uuid_command) {
  uuid_command.accept(*this);
}

void Visitor::visit(const MachO::SymbolCommand& symbol_command) {
  symbol_command.accept(*this);
}

void Visitor::visit(const MachO::SegmentCommand& segment_command) {
  segment_command.accept(*this);
}

void Visitor::visit(const MachO::Section& section) {
  section.accept(*this);
}

void Visitor::visit(const MachO::MainCommand& main_command) {
  main_command.accept(*this);
}

void Visitor::visit(const MachO::DynamicSymbolCommand& dyn_sym_cmd) {
  dyn_sym_cmd.accept(*this);
}

void Visitor::visit(const MachO::DylinkerCommand& dylinker_command) {
  dylinker_command.accept(*this);
}

void Visitor::visit(const MachO::DylibCommand& dylib_command) {
  dylib_command.accept(*this);
}

void Visitor::visit(const MachO::Symbol& symbol) {
  symbol.accept(*this);
}

void Visitor::visit(const MachO::Relocation& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const MachO::RelocationObject& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const MachO::RelocationDyld& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const MachO::BindingInfo& binding_info) {
  binding_info.accept(*this);
}

void Visitor::visit(const MachO::ExportInfo& export_info) {
  export_info.accept(*this);
}





}
