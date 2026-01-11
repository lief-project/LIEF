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
#include <cstdint>

#include "LIEF/COFF/Header.hpp"
#include "LIEF/COFF/RegularHeader.hpp"
#include "LIEF/COFF/BigObjHeader.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class COFF_Header : public Mirror<LIEF::COFF::Header> {
  public:
  using lief_t = LIEF::COFF::Header;
  using Mirror::Mirror;

  auto machine() const { return to_int(get().machine()); }

  auto nb_sections() const { return get().nb_sections(); }
  auto pointerto_symbol_table() const { return get().pointerto_symbol_table(); }
  auto nb_symbols() const { return get().nb_symbols(); }
  auto timedatestamp() const { return get().timedatestamp(); }

  auto to_string() const { return get().to_string(); }

};

class COFF_RegularHeader : public COFF_Header {
  public:
  using lief_t = LIEF::COFF::RegularHeader;

  auto sizeof_optionalheader() const {
    return impl().sizeof_optionalheader();
  }

  auto characteristics() const {
    return impl().characteristics();
  }

  static bool classof(const COFF_Header& hdr) {
    return lief_t::classof(&hdr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class COFF_BigObjHeader : public COFF_Header {
  public:
  using lief_t = LIEF::COFF::BigObjHeader;

  auto version() const {
    return impl().version();
  }

  auto uuid() const {
    return make_span(impl().uuid());
  }

  auto sizeof_data() const {
    return impl().sizeof_data();
  }

  auto flags() const {
    return impl().flags();
  }

  auto metadata_size() const {
    return impl().metadata_size();
  }

  auto metadata_offset() const {
    return impl().metadata_offset();
  }

  static bool classof(const COFF_Header& hdr) {
    return lief_t::classof(&hdr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
