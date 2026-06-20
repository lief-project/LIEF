/* Copyright 2024 - 2026 R. Thomas
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

#include "LIEF/MachO/LazyLoadDylibInfo.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class MachO_LazyLoadDylibInfo_Fixup
  : public Mirror<LIEF::MachO::LazyLoadDylibInfo::Fixup> {
  public:
  using lief_t = LIEF::MachO::LazyLoadDylibInfo::Fixup;
  using Mirror::Mirror;

  auto address() const {
    return get().address();
  }
  auto ordinal() const {
    return get().ordinal();
  }
  auto symbol() const {
    return to_unique_string(get().symbol());
  }
  auto is_auth() const {
    return get().is_auth();
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};

class MachO_LazyLoadDylibInfo : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::LazyLoadDylibInfo;

  class it_fixups
    : public Iterator<MachO_LazyLoadDylibInfo_Fixup, lief_t::it_const_fixups> {
    public:
    it_fixups(const MachO_LazyLoadDylibInfo::lief_t& src) :
      Iterator(src.fixups()) {}
    auto next() { // NOLINT
      return Iterator::next();
    }
    auto size() const { // NOLINT
      return Iterator::size();
    }
  };

  MachO_LazyLoadDylibInfo(const lief_t& base) :
    MachO_Command(base) {}

  auto data_offset() const {
    return impl().data_offset();
  }
  auto data_size() const {
    return impl().data_size();
  }

  auto content() const {
    return make_span(impl().content());
  }

  auto load_path() const {
    return to_unique_string(impl().load_path());
  }

  auto flag_image_offset() const {
    return impl().flag_image_offset();
  }

  auto flags() const {
    return impl().flags();
  }

  auto may_be_missing() const {
    return impl().may_be_missing();
  }

  auto pointer_format() const {
    return impl().pointer_format();
  }

  auto chain_start_image_offset() const {
    return impl().chain_start_image_offset();
  }

  auto symbols() const {
    return make_unique_vector<std::string>(impl().symbols());
  }

  auto fixups() const {
    return std::make_unique<it_fixups>(impl());
  }

  void set_load_path(const std::string& value) {
    impl().load_path(value);
  }

  void set_flag_image_offset(uint32_t value) {
    impl().flag_image_offset(value);
  }

  void set_flags(uint16_t value) {
    impl().flags(value);
  }

  void set_may_be_missing(bool value) {
    impl().may_be_missing(value);
  }

  void set_pointer_format(uint16_t value) {
    impl().pointer_format(value);
  }

  void set_chain_start_image_offset(uint32_t value) {
    impl().chain_start_image_offset(value);
  }

  void add_symbol(const std::string& value) {
    impl().add_symbol(value);
  }

  void clear_symbols() {
    impl().clear_symbols();
  }

  static auto classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
  lief_t& impl() {
    return as<lief_t>(this);
  }
};

using MachO_LazyLoadDylibInfo_it_fixups = MachO_LazyLoadDylibInfo::it_fixups;
