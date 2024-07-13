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
#include "LIEF/DWARF/types/ClassLike.hpp"
#include "LIEF/rust/DWARF/Type.hpp"

#include "LIEF/rust/Iterator.hpp"

class DWARF_types_ClassLike_Member : private Mirror<LIEF::dwarf::types::ClassLike::Member> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::types::ClassLike::Member;

  auto name() const { return get().name(); }

  uint64_t bit_offset(uint32_t& err) const {
    return details::make_error<uint64_t>(
        get().bit_offset(), err
    );
  }

  uint64_t offset(uint32_t& err) const {
    return details::make_error<uint64_t>(
        get().offset(), err
    );
  }

  auto is_declaration() const {
    return get().is_declaration();
  }

  auto is_external() const {
    return get().is_external();
  }

  auto get_type() const {
    return details::try_unique<DWARF_Type>(get().type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};


class DWARF_types_ClassLike : public DWARF_Type {
  public:
  using lief_t = LIEF::dwarf::types::ClassLike;

  class it_members :
      public ContainerIterator<DWARF_types_ClassLike_Member,
                               std::vector<LIEF::dwarf::types::ClassLike::Member>>
  {
    public:
    using container_t = std::vector<LIEF::dwarf::types::ClassLike::Member>;
    it_members(container_t content)
      : ContainerIterator(std::move(content)) { }
    auto next() { return ContainerIterator::next(); }
  };

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }

  auto find_member(uint64_t offset) const {
    return details::try_unique<DWARF_types_ClassLike_Member>(impl().find_member(offset)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto members() const {
    std::vector<LIEF::dwarf::types::ClassLike::Member> members = impl().members();
    return std::make_unique<it_members>(std::move(members));
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};

class DWARF_types_Structure : public DWARF_types_ClassLike {
  public:
  using lief_t = LIEF::dwarf::types::Structure;

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }
};

class DWARF_types_Class : public DWARF_types_ClassLike {
  public:
  using lief_t = LIEF::dwarf::types::Class;

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }
};

class DWARF_types_Union : public DWARF_types_ClassLike {
  public:
  using lief_t = LIEF::dwarf::types::Union;

  static bool classof(const DWARF_Type& type) {
    return lief_t::classof(&type.get());
  }
};
