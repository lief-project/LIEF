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
#include "LIEF/rust/optional.hpp"
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/Metadata.hpp"
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataARM64.hpp"
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataX86.hpp"

class PE_CHPEMetadata : public Mirror<LIEF::PE::CHPEMetadata> {
  public:
  using lief_t = LIEF::PE::CHPEMetadata;
  using Mirror::Mirror;

  auto version() const { return get().version(); }
  auto to_string() const { return get().to_string(); }
};


class PE_CHPEMetadataARM64_range_entry_t : public Mirror<LIEF::PE::CHPEMetadataARM64::range_entry_t> {
  public:
  using lief_t = LIEF::PE::CHPEMetadata;
  using Mirror::Mirror;

  auto start_offset() const { return get().start_offset; }
  auto length() const { return get().length; }
  auto start() const { return get().start(); }
  auto get_type() const { return (uint32_t)to_int(get().type()); }
  auto end() const { return get().end(); }
};


class PE_CHPEMetadataARM64_redirection_entry_t : public Mirror<LIEF::PE::CHPEMetadataARM64::redirection_entry_t> {
  public:
  using lief_t = LIEF::PE::CHPEMetadata;
  using Mirror::Mirror;
  auto src() const { return get().src; }
  auto dst() const { return get().dst; }
};

class PE_CHPEMetadataARM64 : public PE_CHPEMetadata {
  public:
  using lief_t = LIEF::PE::CHPEMetadataARM64;

  class it_const_range_entries :
      public Iterator<PE_CHPEMetadataARM64_range_entry_t, LIEF::PE::CHPEMetadataARM64::it_const_range_entries>
  {
    public:
    it_const_range_entries(const PE_CHPEMetadataARM64::lief_t& src)
      : Iterator(std::move(src.code_ranges())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_const_redirection_entries :
      public Iterator<PE_CHPEMetadataARM64_redirection_entry_t, LIEF::PE::CHPEMetadataARM64::it_const_redirection_entries>
  {
    public:
    it_const_redirection_entries(const PE_CHPEMetadataARM64::lief_t& src)
      : Iterator(std::move(src.redirections())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  auto code_map() const { return impl().code_map(); }
  auto code_map_count() const { return impl().code_map_count(); }
  auto code_ranges_to_entrypoints() const { return impl().code_ranges_to_entrypoints(); }
  auto redirection_metadata() const { return impl().redirection_metadata(); }
  auto os_arm64x_dispatch_call_no_redirect() const { return impl().os_arm64x_dispatch_call_no_redirect(); }
  auto os_arm64x_dispatch_ret() const { return impl().os_arm64x_dispatch_ret(); }
  auto os_arm64x_dispatch_call() const { return impl().os_arm64x_dispatch_call(); }
  auto os_arm64x_dispatch_icall() const { return impl().os_arm64x_dispatch_icall(); }
  auto os_arm64x_dispatch_icall_cfg() const { return impl().os_arm64x_dispatch_icall_cfg(); }
  auto alternate_entry_point() const { return impl().alternate_entry_point(); }
  auto auxiliary_iat() const { return impl().auxiliary_iat(); }
  auto code_ranges_to_entry_points_count() const { return impl().code_ranges_to_entry_points_count(); }
  auto redirection_metadata_count() const { return impl().redirection_metadata_count(); }
  auto get_x64_information_function_pointer() const { return impl().get_x64_information_function_pointer(); }
  auto set_x64_information_function_pointer() const { return impl().set_x64_information_function_pointer(); }
  auto extra_rfe_table() const { return impl().extra_rfe_table(); }
  auto extra_rfe_table_size() const { return impl().extra_rfe_table_size(); }
  auto os_arm64x_dispatch_fptr() const { return impl().os_arm64x_dispatch_fptr(); }
  auto auxiliary_iat_copy() const { return impl().auxiliary_iat_copy(); }
  auto auxiliary_delay_import() const { return impl().auxiliary_delay_import(); }
  auto auxiliary_delay_import_copy() const { return impl().auxiliary_delay_import_copy(); }
  auto bitfield_info() const { return impl().bitfield_info(); }

  auto code_ranges() const {
    return std::make_unique<it_const_range_entries>(impl());
  }

  auto redirections() const {
    return std::make_unique<it_const_redirection_entries>(impl());
  }

  static bool classof(const PE_CHPEMetadata* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class PE_CHPEMetadataX86 : public PE_CHPEMetadata {
  public:
  using lief_t = LIEF::PE::CHPEMetadataX86;

  auto chpe_code_address_range_offset() const {
    return impl().chpe_code_address_range_offset();
  }

  auto chpe_code_address_range_count() const {
    return impl().chpe_code_address_range_count();
  }

  auto wowa64_exception_handler_function_pointer() const {
    return impl().wowa64_exception_handler_function_pointer();
  }

  auto wowa64_dispatch_call_function_pointer() const {
    return impl().wowa64_dispatch_call_function_pointer();
  }

  auto wowa64_dispatch_indirect_call_function_pointer() const {
    return impl().wowa64_dispatch_indirect_call_function_pointer();
  }

  auto wowa64_dispatch_indirect_call_cfg_function_pointer() const {
    return impl().wowa64_dispatch_indirect_call_cfg_function_pointer();
  }

  auto wowa64_dispatch_ret_function_pointer() const {
    return impl().wowa64_dispatch_ret_function_pointer();
  }

  auto wowa64_dispatch_ret_leaf_function_pointer() const {
    return impl().wowa64_dispatch_ret_leaf_function_pointer();
  }

  auto wowa64_dispatch_jump_function_pointer() const {
    return impl().wowa64_dispatch_jump_function_pointer();
  }

  auto compiler_iat_pointer(uint32_t& is_set) const {
    return details::make_optional(impl().compiler_iat_pointer(), is_set);
  }

  auto wowa64_rdtsc_function_pointer(uint32_t& is_set) const {
    return details::make_optional(impl().wowa64_rdtsc_function_pointer(), is_set);
  }

  static bool classof(const PE_CHPEMetadata* meta) {
    return lief_t::classof(&meta->get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
