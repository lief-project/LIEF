/* Copyright 2021 - 2022 R. Thomas
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
#include "Layout.hpp"

#include <LIEF/iostream.hpp>

#include "Builder.tcc"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Symbol.hpp"

namespace LIEF {
namespace ELF {
Layout::Layout(Binary& bin) : binary_{&bin} {}

Layout::~Layout() = default;

bool Layout::is_strtab_shared_shstrtab() const {
  // Check if the .strtab is shared with the .shstrtab
  const size_t shstrtab_idx = binary_->header().section_name_table_idx();
  size_t strtab_idx = 0;

  const Section* symtab = binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB);
  if (symtab == nullptr) {
    return false;
  }
  strtab_idx = symtab->link();

  bool is_shared = true;
  const size_t nb_sections = binary_->sections().size();
  is_shared = is_shared && strtab_idx > 0 && shstrtab_idx > 0;
  is_shared =
      is_shared && strtab_idx < nb_sections && shstrtab_idx < nb_sections;
  is_shared = is_shared && strtab_idx == shstrtab_idx;
  return is_shared;
}

size_t Layout::section_strtab_size() {
  // could be moved in the class base.
  if (!raw_strtab_.empty()) {
    return raw_strtab_.size();
  }

  if (is_strtab_shared_shstrtab()) {
    // The content of .strtab is merged with .shstrtab
    return 0;
  }

  vector_iostream raw_strtab;
  raw_strtab.write<uint8_t>(0);

  size_t offset_counter = raw_strtab.tellp();

  if (binary_->static_symbols_.empty()) {
    return 0;
  }

  std::vector<std::string> symstr_opt =
      Builder::optimize<Symbol, decltype(binary_->static_symbols_)>(
          binary_->static_symbols_,
          [](const std::unique_ptr<Symbol>& sym) { return sym->name(); },
          offset_counter, &strtab_name_map_);
  for (const std::string& name : symstr_opt) {
    raw_strtab.write(name);
  }
  raw_strtab.move(raw_strtab_);
  return raw_strtab_.size();
}

size_t Layout::section_shstr_size() {
  if (!raw_shstrtab_.empty()) {
    // Already in the cache
    return raw_shstrtab_.size();
  }

  vector_iostream raw_shstrtab;

  // In the ELF format all the .str sections
  // start with a null entry.
  raw_shstrtab.write<uint8_t>(0);
  std::vector<std::string> sec_names;
  sec_names.reserve(binary_->sections_.size());
  std::transform(std::begin(binary_->sections_), std::end(binary_->sections_),
                 std::back_inserter(sec_names),
                 [](const std::unique_ptr<Section>& s) { return s->name(); });

  if (!binary_->static_symbols_.empty()) {
    if (binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB) == nullptr) {
      sec_names.push_back(".symtab");
    }
    if (binary_->get(ELF_SECTION_TYPES::SHT_SYMTAB) == nullptr) {
      sec_names.push_back(".strtab");
    }
  }

  // First write section names
  size_t offset_counter = raw_shstrtab.tellp();
  std::vector<std::string> shstrtab_opt =
      Builder::optimize<Section, decltype(sec_names)>(
          sec_names, [](const std::string& s) { return s; }, offset_counter,
          &shstr_name_map_);

  for (const std::string& name : shstrtab_opt) {
    raw_shstrtab.write(name);
  }

  // Check if the .shstrtab and the .strtab are shared (optimization used by
  // clang) in this case, include the static symbol names
  if (!binary_->static_symbols_.empty() && is_strtab_shared_shstrtab()) {
    offset_counter = raw_shstrtab.tellp();
    std::vector<std::string> symstr_opt =
        Builder::optimize<Symbol, decltype(binary_->static_symbols_)>(
            binary_->static_symbols_,
            [](const std::unique_ptr<Symbol>& sym) { return sym->name(); },
            offset_counter, &shstr_name_map_);
    for (const std::string& name : symstr_opt) {
      raw_shstrtab.write(name);
    }
  }

  raw_shstrtab.move(raw_shstrtab_);
  return raw_shstrtab_.size();
}

}  // namespace ELF
}  // namespace LIEF
