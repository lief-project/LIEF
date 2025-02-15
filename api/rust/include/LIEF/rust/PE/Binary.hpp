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
#include <string>
#include <memory>
#include <LIEF/PE.hpp>
#include "LIEF/rust/PE/DosHeader.hpp"
#include "LIEF/rust/PE/Section.hpp"
#include "LIEF/rust/PE/Import.hpp"
#include "LIEF/rust/PE/Header.hpp"
#include "LIEF/rust/PE/OptionalHeader.hpp"
#include "LIEF/rust/PE/DataDirectories.hpp"
#include "LIEF/rust/PE/Relocation.hpp"
#include "LIEF/rust/PE/Export.hpp"
#include "LIEF/rust/PE/TLS.hpp"
#include "LIEF/rust/PE/DelayImport.hpp"
#include "LIEF/rust/PE/debug/Debug.hpp"
#include "LIEF/rust/PE/RichHeader.hpp"
#include "LIEF/rust/PE/ResourceNode.hpp"
#include "LIEF/rust/PE/ResourcesManager.hpp"
#include "LIEF/rust/PE/Symbol.hpp"
#include "LIEF/rust/PE/ExceptionInfo.hpp"
#include "LIEF/rust/PE/LoadConfiguration/LoadConfiguration.hpp"
#include "LIEF/rust/PE/signature/Signature.hpp"
#include "LIEF/rust/PE/debug/CodeViewPDB.hpp"
#include "LIEF/rust/Abstract/Binary.hpp"

class PE_Binary_write_config_t {
  public:
  static auto create() {
    return std::make_unique<PE_Binary_write_config_t>();
  }
  void set_import(bool value) {
    config_.imports = value;
  }

  void set_exports(bool value) {
    config_.exports = value;
  }

  void set_resources(bool value) {
    config_.resources = value;
  }

  void set_relocations(bool value) {
    config_.relocations = value;
  }

  void set_load_config(bool value) {
    config_.load_configuration = value;
  }

  void set_tls(bool value) {
    config_.tls = value;
  }

  void set_overlay(bool value) {
    config_.overlay = value;
  }

  void set_debug(bool value) {
    config_.debug = value;
  }

  void set_dos_stub(bool value) {
    config_.dos_stub = value;
  }

  void set_rsrc_section(std::string sec) {
    config_.rsrc_section = std::move(sec);
  }

  void set_idata_section(std::string sec) {
    config_.idata_section = std::move(sec);
  }

  void set_tls_section(std::string sec) {
    config_.tls_section = std::move(sec);
  }

  void set_reloc_section(std::string sec) {
    config_.reloc_section = std::move(sec);
  }

  void set_export_section(std::string sec) {
    config_.export_section = std::move(sec);
  }

  void set_debug_section(std::string sec) {
    config_.debug_section = std::move(sec);
  }

  const LIEF::PE::Builder::config_t& conf() const {
    return config_;
  }

  private:
  LIEF::PE::Builder::config_t config_;
};

class PE_ParserConfig {
  public:
  static auto create() {
    return std::make_unique<PE_ParserConfig>();
  }

  const LIEF::PE::ParserConfig& conf() const {
    return config_;
  }

  void set_parse_signature(bool value) {
    config_.parse_signature = value;
  }

  void set_parse_exports(bool value) {
    config_.parse_exports = value;
  }

  void set_parse_imports(bool value) {
    config_.parse_imports = value;
  }

  void set_parse_rsrc(bool value) {
    config_.parse_rsrc = value;
  }

  void set_parse_reloc(bool value) {
    config_.parse_reloc = value;
  }

  void set_parse_exceptions(bool value) {
    config_.parse_exceptions = value;
  }

  void set_parse_arm64x_binary(bool value) {
    config_.parse_arm64x_binary = value;
  }

  private:
  LIEF::PE::ParserConfig config_;
};

class PE_Binary : public AbstractBinary {
  public:
  using lief_t = LIEF::PE::Binary;

  class it_debug :
      public Iterator<PE_Debug, LIEF::PE::Binary::it_const_debug_entries>
  {
    public:
    it_debug(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.debug())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_signatures :
      public Iterator<PE_Signature, LIEF::PE::Binary::it_const_signatures>
  {
    public:
    it_signatures(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.signatures())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_sections :
      public Iterator<PE_Section, LIEF::PE::Binary::it_const_sections>
  {
    public:
    it_sections(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_relocations :
      public Iterator<PE_Relocation, LIEF::PE::Binary::it_const_relocations>
  {
    public:
    it_relocations(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_imports :
      public Iterator<PE_Import, LIEF::PE::Binary::it_const_imports>
  {
    public:
    it_imports(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.imports())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_delay_imports :
      public Iterator<PE_DelayImport, LIEF::PE::Binary::it_const_delay_imports>
  {
    public:
    it_delay_imports(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.delay_imports())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_data_directories :
      public Iterator<PE_DataDirectory, LIEF::PE::Binary::it_const_data_directories>
  {
    public:
    it_data_directories(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.data_directories())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_strings_table :
      public Iterator<PE_COFFString, LIEF::PE::Binary::it_const_strings_table>
  {
    public:
    it_strings_table(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.coff_string_table())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols :
      public Iterator<PE_Symbol, LIEF::PE::Binary::it_const_symbols>
  {
    public:
    it_symbols(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_exceptions :
      public Iterator<PE_ExceptionInfo, LIEF::PE::Binary::it_const_exceptions>
  {
    public:
    it_exceptions(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.exceptions())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  PE_Binary(std::unique_ptr<LIEF::PE::Binary> bin) :
    AbstractBinary(std::move(bin))
  {}

  PE_Binary(std::unique_ptr<LIEF::Binary> bin) :
    AbstractBinary(std::move(bin))
  {}

  static auto parse(std::string path) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_Binary>(LIEF::PE::Parser::parse(path));
  }

  static auto parse_with_config(std::string path, const PE_ParserConfig& config) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_Binary>(LIEF::PE::Parser::parse(path, config.conf()));
  }

  auto debug() const {
    return std::make_unique<it_debug>(impl());
  }

  auto signatures() const {
    return std::make_unique<it_signatures>(impl());
  }

  auto sections() const {
    return std::make_unique<it_sections>(impl());
  }

  auto relocations() const {
    return std::make_unique<it_relocations>(impl());
  }

  auto imports() const {
    return std::make_unique<it_imports>(impl());
  }

  auto delay_imports() const {
    return std::make_unique<it_delay_imports>(impl());
  }

  auto data_directories() const {
    return std::make_unique<it_data_directories>(impl());
  }

  auto tls() const {
    return details::try_unique<PE_TLS>(impl().tls()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto rich_header() const {
    return details::try_unique<PE_RichHeader>(impl().rich_header()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto get_export() const {
    return details::try_unique<PE_Export>(impl().get_export()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto resources() const {
    return details::try_unique<PE_ResourceNode>(impl().resources()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto load_configuration() const {
    return details::try_unique<PE_LoadConfiguration>(impl().load_configuration()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto dos_header() const {
    return std::make_unique<PE_DosHeader>(impl().dos_header());
  }

  auto header() const {
    return std::make_unique<PE_Header>(impl().header());
  }

  auto optional_header() const {
    return std::make_unique<PE_OptionalHeader>(impl().optional_header());
  }

  uint32_t compute_checksum() const { return impl().compute_checksum(); }

  auto resources_manager() const {
    return details::from_result<PE_ResourcesManager>(impl().resources_manager()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto verify_signature(uint32_t flags) const {
    using check_t = LIEF::PE::Signature::VERIFICATION_CHECKS;
    return to_int(impl().verify_signature(check_t(flags)));
  }

  auto verify_with_signature(const PE_Signature& sig, uint32_t flags) const {
    using check_t = LIEF::PE::Signature::VERIFICATION_CHECKS;
    return to_int(impl().verify_signature(sig.get(), check_t(flags)));
  }

  std::vector<uint8_t> authentihash(uint32_t algo) const {
    return impl().authentihash(LIEF::PE::ALGORITHMS(algo));
  }

  auto overlay() const {
    return make_span(impl().overlay());
  }

  auto overlay_offset() const {
    return impl().overlay_offset();
  }

  auto dos_stub() const {
    return make_span(impl().dos_stub());
  }

  auto rva_to_offset(uint64_t rva) const {
    return impl().rva_to_offset(rva);
  }

  auto va_to_offset(uint64_t rva) const {
    return impl().va_to_offset(rva);
  }

  uint64_t virtual_size() const {
    return impl().virtual_size();
  }

  uint64_t sizeof_headers() const {
    return impl().sizeof_headers();
  }

  auto section_from_offset(uint64_t offset) const {
    return details::try_unique<PE_Section>(impl().section_from_offset(offset)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto section_from_rva(uint64_t address) const {
    return details::try_unique<PE_Section>(impl().section_from_offset(address)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto section_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_Section>(impl().get_section(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto data_directory_by_type(uint32_t type) const {
    return details::try_unique<PE_DataDirectory>(impl().data_directory(LIEF::PE::DataDirectory::TYPES(type))); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto import_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_Import>(impl().get_import(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto delay_import_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_DelayImport>(impl().get_delay_import(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto export_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().export_dir());
  }

  auto import_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().import_dir());
  }

  auto rsrc_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().rsrc_dir());
  }

  auto exceptions_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().exceptions_dir());
  }

  auto cert_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().cert_dir());
  }

  auto relocation_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().relocation_dir());
  }

  auto debug_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().debug_dir());
  }

  auto tls_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().tls_dir());
  }

  auto load_config_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().load_config_dir());
  }

  auto iat_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().iat_dir());
  }

  auto delay_dir() const {
    return details::try_unique<PE_DataDirectory>(impl().delay_dir());
  }

  Span get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const {
    return make_span(impl().get_content_from_virtual_address(virtual_address, size));
  }

  auto functions() const {
    return std::make_unique<AbstractBinary::it_functions>(impl().functions());
  }

  auto add_import(std::string name) {
    return std::make_unique<PE_Import>(impl().add_import(name));
  }

  void remove_import(std::string name) {
    impl().remove_import(name);
  }

  void remove_all_imports() {
    impl().remove_all_imports();
  }

  void remove_tls() {
    impl().remove_tls();
  }

  void set_tls(const PE_TLS& tls) {
    impl().tls(tls.get());
  }

  void set_resources(const PE_ResourceNode& node) {
    impl().set_resources(node.get());
  }

  auto add_debug_info(const PE_Debug& entry) {
    return details::try_unique<PE_Debug>(impl().add_debug_info(entry.get()));
  }

  bool remove_debug(const PE_Debug& entry) {
    return impl().remove_debug(entry.get());
  }

  bool clear_debug() {
    return impl().clear_debug();
  }

  auto codeview_pdb() const {
    return details::try_unique<PE_CodeViewPDB>(impl().codeview_pdb());
  }

  auto coff_string_table() const {
    return std::make_unique<it_strings_table>(impl());
  }

  auto find_coff_string_at(uint32_t offset) const {
    return details::try_unique<PE_COFFString>(impl().find_coff_string(offset));
  }

  auto symbols() const {
    return std::make_unique<it_symbols>(impl());
  }

  auto exceptions() const {
    return std::make_unique<it_exceptions>(impl());
  }

  auto find_exception_at(uint32_t rva) const {
    return details::try_unique<PE_ExceptionInfo>(impl().find_exception_at(rva));
  }

  auto is_arm64x() const { return impl().is_arm64x(); }

  auto is_arm64ec() const { return impl().is_arm64ec(); }

  auto nested_pe_binary() const {
    return details::try_unique<PE_Binary>(const_cast<lief_t&>(impl()).move_nested_pe_binary());
  }

  void write(std::string output) { impl().write(output); }

  void write_with_config(std::string output, const PE_Binary_write_config_t& config) {
    impl().write(output, config.conf());
  }

  void set_export(const PE_Export& exp) {
    impl().set_export(exp.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
