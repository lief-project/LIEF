/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/DWARF/types/Array.hpp"
#include "LIEF/rust/DWARF/Type.hpp"

class DWARF_types_array_size_info :
  private Mirror<LIEF::dwarf::types::Array::size_info_t>
{
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::types::Array::size_info_t;

  auto name() const { return get().name; }

  uint64_t size() const { return get().size; }

  auto get_type() const {
    return details::try_unique<DWARF_Type>(get().type.get()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};

class DWARF_types_Array : public DWARF_Type {
  public:
  using lief_t = LIEF::dwarf::types::Array;

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }

  auto underlying_type() const {
    return details::try_unique<DWARF_Type>(impl().underlying_type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto size_info() const {
    return std::make_unique<DWARF_types_array_size_info>(impl().size_info());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
