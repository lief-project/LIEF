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
#include "LIEF/DWARF/Location.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/optional.hpp"
#include "LIEF/rust/range.hpp"

#include <memory>
#include <vector>

class DWARF_Location : public Mirror<LIEF::dwarf::Location> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Location;

  auto get_type() const {
    return to_int(get().type);
  }

  auto to_string() const {
    return std::make_unique<std::string>(get().to_string());
  }
};

class DWARF_RegisterLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::RegisterLoc;

  auto id() const {
    return impl().id;
  }

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

class DWARF_AddressLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::AddressLoc;

  auto address() const {
    return impl().address;
  }

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

class DWARF_FrameBaseLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::FrameBaseLoc;

  auto offset() const {
    return impl().offset;
  }

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

class DWARF_RegisterOffsetLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::RegisterOffsetLoc;

  auto id() const {
    return impl().id;
  }

  auto offset() const {
    return impl().offset;
  }

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

class DWARF_ExpressionLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::ExpressionLoc;

  auto expression() const {
    return make_span(impl().expression);
  }

  auto description() const {
    return std::make_unique<std::string>(impl().description);
  }

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

class DWARF_UnavailableLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::UnavailableLoc;

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }
};

class DWARF_CompositeLocation_Piece
  : private Mirror<LIEF::dwarf::CompositeLocation::Piece> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::CompositeLocation::Piece;

  auto kind() const {
    return to_int(get().kind);
  }

  auto bit_size() const {
    return get().bit_size;
  }

  auto bit_offset() const {
    return get().bit_offset;
  }

  uint64_t source_bit_offset(uint32_t& is_set) const {
    return details::make_optional(get().source_bit_offset, is_set);
  }

  auto location() const {
    return details::try_unique<DWARF_Location>(get().location.get());
  }
};

class DWARF_CompositeLocation : public DWARF_Location {
  public:
  using lief_t = LIEF::dwarf::CompositeLocation;

  class it_pieces
    : public ForwardIterator<
          DWARF_CompositeLocation_Piece,
          std::vector<LIEF::dwarf::CompositeLocation::Piece>::const_iterator
      > {
    public:
    it_pieces(const LIEF::dwarf::CompositeLocation& src) :
      ForwardIterator(src.pieces.cbegin(), src.pieces.cend()) {}
    auto next() {
      return ForwardIterator::next();
    }
    auto size() const {
      return ForwardIterator::size();
    }
  };

  auto pieces() const {
    return std::make_unique<it_pieces>(impl());
  }

  static auto classof(const DWARF_Location& loc) {
    return lief_t::classof(&loc.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

using DWARF_CompositeLocation_it_pieces = DWARF_CompositeLocation::it_pieces;

class DWARF_LocationEntry : private Mirror<LIEF::dwarf::LocationEntry> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::LocationEntry;

  Range range(uint32_t& is_set) const {
    if (!get().range) {
      is_set = 0;
      return {};
    }
    is_set = 1;
    return details::make_range(*get().range);
  }

  uint64_t section_index(uint32_t& is_set) const {
    return details::make_optional(get().section_index, is_set);
  }

  auto location() const {
    return details::try_unique<DWARF_Location>(get().location.get());
  }

  auto to_string() const {
    return std::make_unique<std::string>(get().to_string());
  }
};

/// Iterator over the location entries (owned) of a parameter or a variable
class DWARF_it_locations
  : public ContainerIterator<DWARF_LocationEntry,
                             std::vector<LIEF::dwarf::LocationEntry>> {
  public:
  using container_t = std::vector<LIEF::dwarf::LocationEntry>;
  DWARF_it_locations(container_t content) :
    ContainerIterator(std::move(content)) {}
  auto next() {
    return ContainerIterator::next();
  }
  auto size() const {
    return ContainerIterator::size();
  }
};
