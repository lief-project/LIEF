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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE.hpp"
#include "Object.tcc"

namespace LIEF {
namespace PE {

Hash::~Hash(void) = default;

size_t Hash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::PE::Hash>(obj);
}

void Hash::visit(const Binary& binary) {
  process(binary.dos_header());
  process(binary.header());
  process(binary.optional_header());

  process(std::begin(binary.data_directories()), std::end(binary.data_directories()));
  process(std::begin(binary.sections()), std::end(binary.sections()));
  process(std::begin(binary.imports()), std::end(binary.imports()));
  process(std::begin(binary.relocations()), std::end(binary.relocations()));
  process(std::begin(binary.symbols()), std::end(binary.symbols()));

  if (binary.has_debug()) {
    process(std::begin(binary.debug()), std::end(binary.debug()));
  }

  if (binary.has_exports()) {
    process(binary.get_export());
  }

  if (binary.has_tls()) {
    process(binary.tls());
  }

  if (binary.has_rich_header()) {
    process(binary.rich_header());
  }

}


void Hash::visit(const DosHeader& dos_header) {
  this->process(dos_header.magic());
  this->process(dos_header.used_bytes_in_the_last_page());
  this->process(dos_header.file_size_in_pages());
  this->process(dos_header.numberof_relocation());
  this->process(dos_header.header_size_in_paragraphs());
  this->process(dos_header.minimum_extra_paragraphs());
  this->process(dos_header.maximum_extra_paragraphs());
  this->process(dos_header.initial_relative_ss());
  this->process(dos_header.initial_sp());
  this->process(dos_header.checksum());
  this->process(dos_header.initial_ip());
  this->process(dos_header.initial_relative_cs());
  this->process(dos_header.addressof_relocation_table());
  this->process(dos_header.overlay_number());
  this->process(dos_header.reserved());
  this->process(dos_header.oem_id());
  this->process(dos_header.oem_info());
  this->process(dos_header.reserved2());
  this->process(dos_header.addressof_new_exeheader());
}

void Hash::visit(const RichHeader& rich_header) {
  this->process(rich_header.key());
  this->process(std::begin(rich_header.entries()), std::end(rich_header.entries()));
}

void Hash::visit(const RichEntry& rich_entry) {
  this->process(rich_entry.id());
  this->process(rich_entry.build_id());
  this->process(rich_entry.count());
}

void Hash::visit(const Header& header) {
  this->process(header.signature());
  this->process(header.machine());
  this->process(header.numberof_sections());
  this->process(header.time_date_stamp());
  this->process(header.pointerto_symbol_table());
  this->process(header.numberof_symbols());
  this->process(header.sizeof_optional_header());
  this->process(header.characteristics());
}

void Hash::visit(const OptionalHeader& optional_header) {
  this->process(static_cast<uint8_t>(optional_header.magic()));
  this->process(optional_header.major_linker_version());
  this->process(optional_header.minor_linker_version());
  this->process(optional_header.sizeof_code());
  this->process(optional_header.sizeof_initialized_data());
  this->process(optional_header.sizeof_uninitialized_data());
  this->process(optional_header.addressof_entrypoint());
  this->process(optional_header.baseof_code());
  if (optional_header.magic() == PE_TYPE::PE32) {
    this->process(optional_header.baseof_data());
  }
  this->process(optional_header.imagebase());
  this->process(optional_header.section_alignment());
  this->process(optional_header.file_alignment());
  this->process(optional_header.major_operating_system_version());
  this->process(optional_header.minor_operating_system_version());
  this->process(optional_header.major_image_version());
  this->process(optional_header.minor_image_version());
  this->process(optional_header.major_subsystem_version());
  this->process(optional_header.minor_subsystem_version());
  this->process(optional_header.win32_version_value());
  this->process(optional_header.sizeof_image());
  this->process(optional_header.sizeof_headers());
  this->process(optional_header.checksum());
  this->process(optional_header.subsystem());
  this->process(optional_header.dll_characteristics());
  this->process(optional_header.sizeof_stack_reserve());
  this->process(optional_header.sizeof_stack_commit());
  this->process(optional_header.sizeof_heap_reserve());
  this->process(optional_header.sizeof_heap_commit());
  this->process(optional_header.loader_flags());
  this->process(optional_header.numberof_rva_and_size());

}

void Hash::visit(const DataDirectory& data_directory) {
  this->process(data_directory.RVA());
  this->process(data_directory.size());
  this->process(data_directory.type());
}

void Hash::visit(const Section& section) {
  this->process(section.name());
  this->process(section.offset());
  this->process(section.size());

  this->process(section.virtual_size());
  this->process(section.virtual_address());
  this->process(section.pointerto_raw_data());
  this->process(section.pointerto_relocation());
  this->process(section.pointerto_line_numbers());
  this->process(section.numberof_relocations());
  this->process(section.numberof_line_numbers());
  this->process(section.characteristics());
  this->process(section.content());

}

void Hash::visit(const Relocation& relocation) {
  this->process(relocation.virtual_address());
  this->process(std::begin(relocation.entries()), std::end(relocation.entries()));
}

void Hash::visit(const RelocationEntry& relocation_entry) {
  this->process(relocation_entry.data());
  this->process(relocation_entry.position());
  this->process(relocation_entry.type());

}

void Hash::visit(const Export& export_) {
  this->process(export_.export_flags());
  this->process(export_.timestamp());
  this->process(export_.major_version());
  this->process(export_.minor_version());
  this->process(export_.ordinal_base());
  this->process(export_.name());
  this->process(std::begin(export_.entries()), std::end(export_.entries()));
}

void Hash::visit(const ExportEntry& export_entry) {
  this->process(export_entry.name());
  this->process(export_entry.ordinal());
  this->process(export_entry.address());
  this->process(export_entry.is_extern());
}

void Hash::visit(const TLS& tls) {
  this->process(tls.addressof_raw_data().first);
  this->process(tls.addressof_raw_data().second);
  this->process(tls.addressof_index());
  this->process(tls.addressof_callbacks());
  this->process(tls.sizeof_zero_fill());
  this->process(tls.characteristics());
  this->process(tls.data_template());
  this->process(tls.callbacks());
}

void Hash::visit(const Symbol& symbol) {

  this->process(symbol.name());
  this->process(symbol.value());
  this->process(symbol.size());

  this->process(symbol.section_number());
  this->process(symbol.type());
  this->process(symbol.base_type());
  this->process(symbol.complex_type());
  this->process(symbol.storage_class());
  this->process(symbol.numberof_aux_symbols());
}

void Hash::visit(const Debug& debug) {
  this->process(debug.characteristics());
  this->process(debug.timestamp());
  this->process(debug.major_version());
  this->process(debug.minor_version());
  this->process(debug.type());
  this->process(debug.sizeof_data());
  this->process(debug.addressof_rawdata());
  this->process(debug.pointerto_rawdata());

  if (debug.has_code_view()) {
    debug.code_view().accept(*this);
  }

}

void Hash::visit(const CodeView& cv) {
  this->process(cv.cv_signature());
}

void Hash::visit(const CodeViewPDB& cvpdb) {
  this->visit(*cvpdb.as<CodeView>());
  this->process(cvpdb.signature());
  this->process(cvpdb.age());
  this->process(cvpdb.filename());
}

void Hash::visit(const Import& import) {

  this->process(import.forwarder_chain());
  this->process(import.timedatestamp());
  this->process(import.import_address_table_rva());
  this->process(import.import_lookup_table_rva());
  this->process(import.name());
  this->process(std::begin(import.entries()), std::end(import.entries()));
}

void Hash::visit(const ImportEntry& import_entry) {
  this->process(import_entry.hint_name_rva());
  this->process(import_entry.hint());
  this->process(import_entry.iat_value());
  this->process(import_entry.name());
  this->process(import_entry.data());
}

void Hash::visit(const ResourceNode& resource_node) {

  this->process(resource_node.id());
  if (resource_node.has_name()) {
    this->process(resource_node.name());
  }

  this->process(std::begin(resource_node.childs()), std::end(resource_node.childs()));
}

void Hash::visit(const ResourceData& resource_data) {
  this->process(*resource_data.as<ResourceNode>());
  this->process(resource_data.code_page());
  this->process(resource_data.content());
}

void Hash::visit(const ResourceDirectory& resource_directory) {
  this->process(*resource_directory.as<ResourceNode>());
  this->process(resource_directory.characteristics());
  this->process(resource_directory.time_date_stamp());
  this->process(resource_directory.major_version());
  this->process(resource_directory.minor_version());
  this->process(resource_directory.numberof_name_entries());
  this->process(resource_directory.numberof_id_entries());
}


void Hash::visit(const ResourcesManager& resources_manager) {

  if (resources_manager.has_manifest()) {
    this->process(resources_manager.manifest());
  }

  if (resources_manager.has_version()) {
    this->process(resources_manager.version());
  }

  if (resources_manager.has_icons()) {
    this->process(std::begin(resources_manager.icons()), std::end(resources_manager.icons()));
  }

  if (resources_manager.has_dialogs()) {
    this->process(std::begin(resources_manager.dialogs()), std::end(resources_manager.dialogs()));
  }
}

void Hash::visit(const ResourceStringFileInfo& resource_sfi) {

  this->process(resource_sfi.type());
  this->process(resource_sfi.key());
  this->process(std::begin(resource_sfi.langcode_items()), std::end(resource_sfi.langcode_items()));
}

void Hash::visit(const ResourceFixedFileInfo& resource_ffi) {

  this->process(resource_ffi.signature());
  this->process(resource_ffi.struct_version());
  this->process(resource_ffi.file_version_MS());
  this->process(resource_ffi.file_version_LS());
  this->process(resource_ffi.product_version_MS());
  this->process(resource_ffi.product_version_LS());
  this->process(resource_ffi.file_flags_mask());
  this->process(resource_ffi.file_flags());
  this->process(resource_ffi.file_os());
  this->process(resource_ffi.file_type());
  this->process(resource_ffi.file_subtype());
  this->process(resource_ffi.file_date_MS());
  this->process(resource_ffi.file_date_LS());
}

void Hash::visit(const ResourceVarFileInfo& resource_vfi) {

  this->process(resource_vfi.type());
  this->process(resource_vfi.key());
  this->process(resource_vfi.translations());
}

void Hash::visit(const LangCodeItem& resource_lci) {

  this->process(resource_lci.type());
  this->process(resource_lci.key());
  for (const std::pair<const std::u16string, std::u16string>& p : resource_lci.items()) {
    this->process(p.first);
    this->process(p.second);
  }
}


void Hash::visit(const ResourceVersion& resource_version) {

  this->process(resource_version.type());
  this->process(resource_version.key());

  if (resource_version.has_fixed_file_info()) {
    this->process(resource_version.fixed_file_info());
  }

  if (resource_version.has_string_file_info()) {
    this->process(resource_version.string_file_info());
  }

  if (resource_version.has_var_file_info()) {
    this->process(resource_version.var_file_info());
  }

}

void Hash::visit(const ResourceIcon& resource_icon) {

  if (resource_icon.id() != static_cast<uint32_t>(-1)) {
    this->process(resource_icon.id());
  }
  this->process(resource_icon.lang());
  this->process(resource_icon.sublang());
  this->process(resource_icon.width());
  this->process(resource_icon.height());
  this->process(resource_icon.color_count());
  this->process(resource_icon.reserved());
  this->process(resource_icon.planes());
  this->process(resource_icon.bit_count());
  this->process(resource_icon.pixels());

}

void Hash::visit(const ResourceDialog& dialog) {

  this->process(dialog.x());
  this->process(dialog.y());
  this->process(dialog.cx());
  this->process(dialog.cy());
  this->process(dialog.style());
  this->process(dialog.extended_style());

  this->process(std::begin(dialog.items()), std::end(dialog.items()));

  if (dialog.is_extended()) {
    this->process(dialog.version());
    this->process(dialog.signature());
    this->process(dialog.help_id());
    this->process(dialog.weight());
    this->process(dialog.point_size());
    this->process(dialog.is_italic());
    this->process(dialog.charset());
    this->process(dialog.title());
    this->process(dialog.typeface());
  }

}


void Hash::visit(const ResourceDialogItem& dialog_item) {
  this->process(dialog_item.x());
  this->process(dialog_item.y());
  this->process(dialog_item.cx());
  this->process(dialog_item.cy());
  this->process(dialog_item.id());
  this->process(dialog_item.style());
  this->process(dialog_item.extended_style());
  if (dialog_item.is_extended()) {
    this->process(dialog_item.help_id());
    this->process(dialog_item.title());
  }
}

void Hash::visit(const ResourceStringTable& string_table) {
  this->process(string_table.length());
  this->process(string_table.name());
}

void Hash::visit(const ResourceAccelerator& accelerator) {
  this->process(accelerator.flags());
  this->process(accelerator.ansi());
  this->process(accelerator.id());
  this->process(accelerator.padding());
}

void Hash::visit(const Signature& signature) {
  this->process(signature.version());
  this->process(signature.digest_algorithm());
  this->process(signature.content_info());
  this->process(std::begin(signature.certificates()), std::end(signature.certificates()));
  this->process(std::begin(signature.signers()), std::end(signature.signers()));
}

void Hash::visit(const x509& x509) {
  this->process(x509.subject());
  this->process(x509.issuer());
  this->process(x509.valid_to());
  this->process(x509.valid_from());
  this->process(x509.signature_algorithm());
  this->process(x509.serial_number());
  this->process(x509.version());
}

void Hash::visit(const SignerInfo& signerinfo) {

  this->process(signerinfo.version());
  this->process(signerinfo.serial_number());
  this->process(signerinfo.issuer());
  this->process(signerinfo.encryption_algorithm());
  this->process(signerinfo.digest_algorithm());
  this->process(signerinfo.encrypted_digest());
  this->process(std::begin(signerinfo.authenticated_attributes()), std::end(signerinfo.authenticated_attributes()));
  this->process(std::begin(signerinfo.unauthenticated_attributes()), std::end(signerinfo.unauthenticated_attributes()));
}

void Hash::visit(const Attribute& attr) {
  this->process(attr.type());
}

void Hash::visit(const ContentInfo& info) {
  this->process(info.content_type());
  this->process(info.digest_algorithm());
  this->process(info.digest());
  this->process(info.file());
}


void Hash::visit(const ContentType& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.oid());
}
void Hash::visit(const GenericType& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.raw_content());
  this->process(attr.oid());
}
void Hash::visit(const MsSpcNestedSignature& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.sig());
}
void Hash::visit(const MsSpcStatementType& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.oid());
}
void Hash::visit(const PKCS9AtSequenceNumber& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.number());
}
void Hash::visit(const PKCS9CounterSignature& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.signer());
}
void Hash::visit(const PKCS9MessageDigest& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.digest());
}
void Hash::visit(const PKCS9SigningTime& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.time());
}
void Hash::visit(const SpcSpOpusInfo& attr) {
  this->visit(*attr.as<Attribute>());
  this->process(attr.program_name());
  this->process(attr.more_info());
}

void Hash::visit(const CodeIntegrity& code_integrity) {
  this->process(code_integrity.flags());
  this->process(code_integrity.catalog());
  this->process(code_integrity.catalog_offset());
  this->process(code_integrity.reserved());
}

void Hash::visit(const LoadConfiguration& config) {
  this->process(config.characteristics());
  this->process(config.timedatestamp());
  this->process(config.major_version());
  this->process(config.minor_version());
  this->process(config.global_flags_clear());
  this->process(config.global_flags_set());
  this->process(config.critical_section_default_timeout());
  this->process(config.decommit_free_block_threshold());
  this->process(config.decommit_total_free_threshold());
  this->process(config.lock_prefix_table());
  this->process(config.maximum_allocation_size());
  this->process(config.virtual_memory_threshold());
  this->process(config.process_affinity_mask());
  this->process(config.process_heap_flags());
  this->process(config.csd_version());
  this->process(config.reserved1());
  this->process(config.editlist());
  this->process(config.security_cookie());
}

void Hash::visit(const LoadConfigurationV0& config) {
  this->process(*config.as<LoadConfiguration>());
  this->process(config.se_handler_table());
  this->process(config.se_handler_count());
}

void Hash::visit(const LoadConfigurationV1& config) {

  this->process(*config.as<LoadConfigurationV0>());
  this->process(config.guard_cf_check_function_pointer());
  this->process(config.guard_cf_dispatch_function_pointer());
  this->process(config.guard_cf_function_table());
  this->process(config.guard_cf_function_count());
  this->process(config.guard_flags());
}

void Hash::visit(const LoadConfigurationV2& config) {

  this->process(*config.as<LoadConfigurationV1>());
  this->process(config.code_integrity());
}

void Hash::visit(const LoadConfigurationV3& config) {
  this->process(*config.as<LoadConfigurationV2>());
  this->process(config.guard_address_taken_iat_entry_table());
  this->process(config.guard_address_taken_iat_entry_count());
  this->process(config.guard_long_jump_target_table());
  this->process(config.guard_long_jump_target_count());
}

void Hash::visit(const LoadConfigurationV4& config) {
  this->process(*config.as<LoadConfigurationV3>());
  this->process(config.dynamic_value_reloc_table());
  this->process(config.hybrid_metadata_pointer());
}

void Hash::visit(const LoadConfigurationV5& config) {
  this->process(*config.as<LoadConfigurationV4>());
  this->process(config.guard_rf_failure_routine());
  this->process(config.guard_rf_failure_routine_function_pointer());
  this->process(config.dynamic_value_reloctable_offset());
  this->process(config.dynamic_value_reloctable_section());
}

void Hash::visit(const LoadConfigurationV6& config) {
  this->process(*config.as<LoadConfigurationV5>());
  this->process(config.guard_rf_verify_stackpointer_function_pointer());
  this->process(config.hotpatch_table_offset());
}

void Hash::visit(const LoadConfigurationV7& config) {
  this->process(*config.as<LoadConfigurationV6>());
  this->process(config.reserved3());
  this->process(config.addressof_unicode_string());
}


void Hash::visit(const Pogo& pogo) {
  it_const_pogo_entries entries = pogo.entries();
  this->process(pogo.signature());
  this->process(std::begin(entries), std::end(entries));
}


void Hash::visit(const PogoEntry& entry) {
  this->process(entry.name());
  this->process(entry.start_rva());
  this->process(entry.size());
}

} // namespace PE
} // namespace LIEF

