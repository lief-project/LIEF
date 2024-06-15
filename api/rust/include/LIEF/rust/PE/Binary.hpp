/* Copyright 2024 R. Thomas
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
#include "LIEF/rust/PE/LoadConfiguration/LoadConfiguration.hpp"
#include "LIEF/rust/PE/signature/Signature.hpp"
#include "LIEF/rust/Abstract/Binary.hpp"

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


  PE_Binary(std::unique_ptr<LIEF::PE::Binary> bin) :
    AbstractBinary(std::move(bin))
  {}

  static auto parse(std::string path) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PE_Binary>(LIEF::PE::Parser::parse(path));
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

  Span get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const {
    return make_span(impl().get_content_from_virtual_address(virtual_address, size));
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
