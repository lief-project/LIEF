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
#include "LIEF/PE/Section.hpp"
#include "LIEF/rust/PE/COFFString.hpp"
#include "LIEF/rust/Abstract/Section.hpp"

class PE_Section : public AbstractSection {
  public:
  using lief_t = LIEF::PE::Section;
  PE_Section(const lief_t& sec) : AbstractSection(sec) {}

  auto sizeof_raw_data() const { return impl().sizeof_raw_data(); }
  auto virtual_size() const { return impl().virtual_size(); }
  auto pointerto_raw_data() const { return impl().pointerto_raw_data(); }
  auto pointerto_relocation() const { return impl().pointerto_relocation(); }
  auto pointerto_line_numbers() const { return impl().pointerto_line_numbers(); }
  auto numberof_relocations() const { return impl().numberof_relocations(); }
  auto numberof_line_numbers() const { return impl().numberof_line_numbers(); }
  auto characteristics() const { return impl().characteristics(); }

  auto is_discardable() const { return impl().is_discardable(); }

  Span padding() const { return make_span(impl().padding()); }

  auto coff_string() const {
    return details::try_unique<PE_COFFString>(impl().coff_string());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
