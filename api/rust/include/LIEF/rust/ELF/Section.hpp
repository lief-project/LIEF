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

#include "LIEF/ELF/Section.hpp"
#include "LIEF/rust/Abstract/Section.hpp"
#include "LIEF/rust/helpers.hpp"

class ELF_Section : public AbstractSection {
  public:
  using lief_t = LIEF::ELF::Section;
  ELF_Section(const lief_t& section) : AbstractSection(section) {}

  uint64_t get_type() const { return to_int(impl().type()); }
  uint64_t flags() const { return impl().flags(); }
  uint64_t alignment() const { return impl().alignment(); }
  uint64_t information() const { return impl().information(); }
  uint64_t entry_size() const { return impl().entry_size(); }
  uint64_t link() const { return impl().link(); }
  uint64_t file_offset() const { return impl().file_offset(); }
  uint64_t original_size() const { return impl().original_size(); }
  Span content() const { return make_span(impl().content()); }

  std::string to_string() const { return details::to_string(impl()); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
