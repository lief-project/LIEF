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

#include "LIEF/PE.hpp"

namespace LIEF {
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


void Visitor::visit(const PE::LoadConfiguration& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV0& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV1& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV2& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV3& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV4& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV5& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV6& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::LoadConfigurationV7& config) {
  config.accept(*this);
}

void Visitor::visit(const PE::CodeIntegrity& code_integrity) {
  code_integrity.accept(*this);
}

}
