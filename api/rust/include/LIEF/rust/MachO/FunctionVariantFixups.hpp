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

#include "LIEF/MachO/FunctionVariantFixups.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/MachO/SegmentCommand.hpp"

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class MachO_FunctionVariantFixups_Fixup
  : public Mirror<LIEF::MachO::FunctionVariantFixups::Fixup> {
  public:
  using lief_t = LIEF::MachO::FunctionVariantFixups::Fixup;
  using Mirror::Mirror;

  auto seg_offset() const {
    return get().seg_offset();
  }
  auto seg_index() const {
    return get().seg_index();
  }
  auto variant_index() const {
    return get().variant_index();
  }
  auto pac_auth() const {
    return get().pac_auth();
  }
  auto pac_address() const {
    return get().pac_address();
  }
  auto pac_key() const {
    return get().pac_key();
  }
  auto pac_diversity() const {
    return get().pac_diversity();
  }

  auto segment() const {
    return details::try_unique<MachO_SegmentCommand>(get().segment());
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};

class MachO_FunctionVariantFixups : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::FunctionVariantFixups;

  class it_fixups
    : public Iterator<MachO_FunctionVariantFixups_Fixup, lief_t::it_const_fixups> {
    public:
    it_fixups(const MachO_FunctionVariantFixups::lief_t& src) :
      Iterator(src.fixups()) {}
    auto next() {
      return Iterator::next();
    }
    auto size() const {
      return Iterator::size();
    }
  };

  MachO_FunctionVariantFixups(const lief_t& base) :
    MachO_Command(base) {}
  uint32_t data_offset() const {
    return impl().data_offset();
  }
  uint32_t data_size() const {
    return impl().data_size();
  }

  auto content() const {
    return make_span(impl().content());
  }

  auto fixups() const {
    return std::make_unique<it_fixups>(impl());
  }

  static auto classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

using MachO_FunctionVariantFixups_it_fixups =
    MachO_FunctionVariantFixups::it_fixups;
