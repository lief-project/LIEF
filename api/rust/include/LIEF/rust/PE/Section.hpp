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
#include "LIEF/PE/Section.hpp"
#include "LIEF/rust/Abstract/Section.hpp"

class PE_Section : public AbstractSection {
  public:
  using lief_t = LIEF::PE::Section;
  PE_Section(const lief_t& sec) : AbstractSection(sec) {}

  uint32_t sizeof_raw_data() const { return impl().sizeof_raw_data(); }
  uint32_t virtual_size() const { return impl().virtual_size(); }
  uint32_t pointerto_raw_data() const { return impl().pointerto_raw_data(); }
  uint32_t pointerto_relocation() const { return impl().pointerto_relocation(); }
  uint32_t pointerto_line_numbers() const { return impl().pointerto_line_numbers(); }
  uint32_t numberof_relocations() const { return impl().numberof_relocations(); }
  uint32_t numberof_line_numbers() const { return impl().numberof_line_numbers(); }
  uint64_t characteristics() const { return impl().characteristics(); }

  Span padding() const { return make_span(impl().padding()); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
