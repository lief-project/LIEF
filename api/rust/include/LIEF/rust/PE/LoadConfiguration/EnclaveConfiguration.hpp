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
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/PE/LoadConfigurations/EnclaveConfiguration.hpp"
#include "LIEF/PE/LoadConfigurations/EnclaveImport.hpp"

class PE_EnclaveImport : public Mirror<LIEF::PE::EnclaveImport> {
  public:
  using lief_t = LIEF::PE::EnclaveImport;
  using Mirror::Mirror;

  auto get_type() const { return to_int(get().type()); }
  auto min_security_version() const { return get().min_security_version(); }
  auto import_name_rva() const { return get().import_name_rva(); }
  std::string import_name() const { return get().import_name(); }
  auto reserved() const { return get().reserved(); }
  auto id() const { return make_span(get().id()); }
  auto family_id() const { return make_span(get().family_id()); }
  auto image_id() const { return make_span(get().image_id()); }

  std::string to_string() const { return get().to_string(); }
};

class PE_EnclaveConfiguration : public Mirror<LIEF::PE::EnclaveConfiguration> {
  public:
  using lief_t = LIEF::PE::EnclaveConfiguration;
  using Mirror::Mirror;

  class it_imports :
      public Iterator<PE_EnclaveImport, LIEF::PE::EnclaveConfiguration::it_const_imports>
  {
    public:
    it_imports(const PE_EnclaveConfiguration::lief_t& src)
      : Iterator(std::move(src.imports())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto size() const { return get().size(); }
  auto min_required_config_size() const { return get().min_required_config_size(); }
  auto policy_flags() const { return get().policy_flags(); }
  auto is_debuggable() const { return get().is_debuggable(); }
  auto import_list_rva() const { return get().import_list_rva(); }
  auto import_entry_size() const { return get().import_entry_size(); }
  uint32_t nb_imports() const { return get().nb_imports(); }
  auto imports() const { return std::make_unique<it_imports>(get()); }
  auto family_id() const { return make_span(get().family_id()); }
  auto image_id() const { return make_span(get().image_id()); }
  auto image_version() const { return get().image_version(); }
  auto security_version() const { return get().security_version(); }
  auto enclave_size() const { return get().enclave_size(); }
  auto nb_threads() const { return get().nb_threads(); }
  auto enclave_flags() const { return get().enclave_flags(); }
  std::string to_string() const { return get().to_string(); }
};


