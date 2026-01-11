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
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class ELF_Segment : public Mirror<LIEF::ELF::Segment> {
  public:
  using lief_t = LIEF::ELF::Segment;
  using Mirror::Mirror;

  static auto create() {
    return std::make_unique<ELF_Segment>(std::make_unique<lief_t>());
  }

  auto stype() const { return to_int(get().type()); }
  auto flags() const { return to_int(get().flags()); }
  auto file_offset() const { return get().file_offset(); }
  auto virtual_address() const { return get().virtual_address(); }
  auto physical_address() const { return get().physical_address(); }
  auto physical_size() const { return get().physical_size(); }
  auto virtual_size() const { return get().virtual_size(); }
  auto alignment() const { return get().alignment(); }

  auto set_flags(uint32_t value) {
    get().flags(value);
  }

  auto set_type(uint64_t ty) {
    get().type((lief_t::TYPE)ty);
  }

  void set_file_offset(uint64_t value) {
    get().file_offset(value);
  }

  void set_virtual_address(uint64_t value) {
    get().virtual_address(value);
  }

  void set_physical_address(uint64_t value) {
    get().physical_address(value);
  }

  void set_virtual_size(uint64_t value) {
    get().virtual_size(value);
  }

  void set_alignment(uint64_t value) {
    get().alignment(value);
  }

  void set_content(const uint8_t* ptr, uint64_t size) {
    get().content({ptr, ptr + size});
  }

  Span content() const { return make_span(get().content()); }

  void fill(char c) { get().fill(c); }
  void clear() { get().clear(); }

  std::string to_string() const { return details::to_string(get()); }
};
