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
#include "LIEF/DWARF/editor/StructType.hpp"
#include "LIEF/rust/DWARF/editor/Type.hpp"


class DWARF_editor_StructType_Member : public Mirror<LIEF::dwarf::editor::StructType::Member> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::editor::StructType::Member;
};

class DWARF_editor_StructType : public DWARF_editor_Type {
  public:
  using DWARF_editor_Type::DWARF_editor_Type;
  using lief_t = LIEF::dwarf::editor::StructType;

  auto set_size(uint64_t size) {
    impl().set_size(size);
  }

  auto add_member(std::string name, const DWARF_editor_Type& ty) {
    return details::try_unique<DWARF_editor_StructType_Member>(
      impl().add_member(name, ty.get())
    );
  }

  auto add_member_with_offset(std::string name, const DWARF_editor_Type& ty,
                              uint64_t offset)
  {
    return details::try_unique<DWARF_editor_StructType_Member>(
      impl().add_member(name, ty.get(), offset)
    );
  }

  auto add_bitfield(std::string name, const DWARF_editor_Type& ty, uint64_t bitsize) {
    return details::try_unique<DWARF_editor_StructType_Member>(
      impl().add_bitfield(name, ty.get(), bitsize)
    );
  }

  auto add_bitfield_with_offset(std::string name, const DWARF_editor_Type& ty, uint64_t bitsize, uint64_t offset) {
    return details::try_unique<DWARF_editor_StructType_Member>(
      impl().add_bitfield(name, ty.get(), bitsize, offset)
    );
  }

  static bool classof(const DWARF_editor_Type& type) {
    return lief_t::classof(&type.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
