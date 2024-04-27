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
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Span.hpp"

class ELF_Segment : private Mirror<LIEF::ELF::Segment> {
  public:
  using lief_t = LIEF::ELF::Segment;
  using Mirror::Mirror;

  uint64_t stype() const { return to_int(get().type()); }
  uint32_t flags() const { return to_int(get().flags()); }
  uint64_t file_offset() const { return get().file_offset(); }
  uint64_t virtual_address() const { return get().virtual_address(); }
  uint64_t physical_address() const { return get().physical_address(); }
  uint64_t physical_size() const { return get().physical_size(); }
  uint64_t virtual_size() const { return get().virtual_size(); }
  uint64_t alignment() const { return get().alignment(); }

  Span content() const { return make_span(get().content()); }

  std::string to_string() const { return details::to_string(get()); }
};
