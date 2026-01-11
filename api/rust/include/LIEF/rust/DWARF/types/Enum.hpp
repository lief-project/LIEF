/* Copyright 2022 - 2026 R. Thomas
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
#include "LIEF/DWARF/types/Enum.hpp"
#include "LIEF/rust/DWARF/Type.hpp"
#include "LIEF/rust/optional.hpp"
#include "LIEF/rust/Iterator.hpp"

class DWARF_types_Enum_Entry : public Mirror<LIEF::dwarf::types::Enum::Entry> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::types::Enum::Entry;

  auto name() const { return get().name(); }

  int64_t value(uint32_t& is_set) const {
    return details::make_optional(get().value(), is_set);
  }
};

class DWARF_types_Enum : public DWARF_Type {
  public:
  using lief_t = LIEF::dwarf::types::Enum;

  class it_entries :
      public ContainerIterator<DWARF_types_Enum_Entry,
                               std::vector<LIEF::dwarf::types::Enum::Entry>>
  {
    public:
    using container_t = std::vector<LIEF::dwarf::types::Enum::Entry>;
    it_entries(container_t content)
      : ContainerIterator(std::move(content)) { }
    auto next() { return ContainerIterator::next(); }
  };

  auto entries() const {
    std::vector<LIEF::dwarf::types::Enum::Entry> entries = impl().entries();
    return std::make_unique<it_entries>(std::move(entries));
  }

  auto underlying_type() const {
    return details::try_unique<DWARF_Type>(impl().underlying_type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  std::unique_ptr<DWARF_types_Enum_Entry> find_entry(int64_t value) const {
    if (auto entry = impl().find_entry(value)) {
      return std::make_unique<DWARF_types_Enum_Entry>(*entry);
    }
    return nullptr;
  }

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
