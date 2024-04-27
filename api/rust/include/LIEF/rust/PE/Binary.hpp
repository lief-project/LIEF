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
      : Iterator(std::move(src.debug())) { }
    auto next() { return Iterator::next(); }
  };

  class it_signatures :
      public Iterator<PE_Signature, LIEF::PE::Binary::it_const_signatures>
  {
    public:
    it_signatures(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.signatures())) { }
    auto next() { return Iterator::next(); }
  };

  class it_sections :
      public Iterator<PE_Section, LIEF::PE::Binary::it_const_sections>
  {
    public:
    it_sections(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { }
    auto next() { return Iterator::next(); }
  };

  class it_relocations :
      public Iterator<PE_Relocation, LIEF::PE::Binary::it_const_relocations>
  {
    public:
    it_relocations(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { }
    auto next() { return Iterator::next(); }
  };

  class it_imports :
      public Iterator<PE_Import, LIEF::PE::Binary::it_const_imports>
  {
    public:
    it_imports(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.imports())) { }
    auto next() { return Iterator::next(); }
  };

  class it_delay_imports :
      public Iterator<PE_DelayImport, LIEF::PE::Binary::it_const_delay_imports>
  {
    public:
    it_delay_imports(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.delay_imports())) { }
    auto next() { return Iterator::next(); }
  };

  class it_data_directories :
      public Iterator<PE_DataDirectory, LIEF::PE::Binary::it_const_data_directories>
  {
    public:
    it_data_directories(const PE_Binary::lief_t& src)
      : Iterator(std::move(src.data_directories())) { }
    auto next() { return Iterator::next(); }
  };


  PE_Binary(std::unique_ptr<LIEF::PE::Binary> bin) :
    AbstractBinary(std::move(bin))
  {}

  static auto parse(std::string path) {
    return std::make_unique<PE_Binary>(LIEF::PE::Parser::parse(path));
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
    return details::try_unique<PE_TLS>(impl().tls());
  }

  auto rich_header() const {
    return details::try_unique<PE_RichHeader>(impl().rich_header());
  }

  auto get_export() const {
    return details::try_unique<PE_Export>(impl().get_export());
  }

  auto resources() const {
    return details::try_unique<PE_ResourceNode>(impl().resources());
  }

  auto load_configuration() const {
    return details::try_unique<PE_LoadConfiguration>(impl().load_configuration());
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

  auto resources_manager() const {
    return details::from_result<PE_ResourcesManager>(impl().resources_manager());
  }

  auto verify_signature(uint32_t flags) const {
    using check_t = LIEF::PE::Signature::VERIFICATION_CHECKS;
    return to_int(impl().verify_signature(check_t(flags)));
  }

  std::vector<uint8_t> authentihash(uint32_t algo) const {
    return impl().authentihash(LIEF::PE::ALGORITHMS(algo));
  }

  auto overlay() const {
    return make_span(impl().overlay());
  }

  auto dos_stub() const {
    return make_span(impl().dos_stub());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
