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
#ifndef LIEF_DWARF_LOCATION_H
#define LIEF_DWARF_LOCATION_H

#include <cstdint>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "LIEF/range.hpp"
#include "LIEF/visibility.h"

namespace LIEF::dwarf {

/// This class represents where the value of a variable or a parameter lives.
/// It interfaces the DWARF location expression (`DW_AT_location`).
class LIEF_API Location {
  public:
  enum class Type : uint8_t {
    UNKNOWN = 0,
    /// The value is associated to a register
    REG,

    /// The value is at a fixed memory address
    ADDRESS,

    /// The value is at an offset of the frame base
    FRAME_BASE,

    /// The value is at an offset of a register
    REGISTER_OFFSET,

    /// An unevaluated DWARF expression
    EXPRESSION,

    /// The value is not available
    UNAVAILABLE,

    /// The value is split in several pieces
    COMPOSITE,
  };

  explicit Location(Type ty) :
    type(ty) {}

  Location(const Location&) = default;
  Location& operator=(const Location&) = default;

  Location(Location&&) noexcept = default;
  Location& operator=(Location&&) noexcept = default;

  virtual ~Location();

  template<class T>
  const T* as() const LIEF_LIFETIMEBOUND {
    if (T::classof(this)) {
      return static_cast<const T*>(this);
    }
    return nullptr;
  }

  /// Human-readable description of this location
  std::string to_string() const;

  friend std::ostream& operator<<(std::ostream& os, const Location& loc) {
    os << loc.to_string();
    return os;
  }

  Type type = Type::UNKNOWN;
};

/// The value is associated to a register (e.g. `DW_OP_reg5`)
class LIEF_API RegisterLoc : public Location {
  public:
  explicit RegisterLoc(uint64_t reg_id) :
    Location(Type::REG),
    id(reg_id) {}

  static bool classof(const Location* loc) {
    return loc->type == Type::REG;
  }

  ~RegisterLoc() override;

  /// DWARF id of the register that must be interpreted according to the target
  /// architecture
  uint64_t id = 0;
};

/// The value is located at a fixed memory address (e.g. `DW_OP_addr`)
class LIEF_API AddressLoc : public Location {
  public:
  explicit AddressLoc(uint64_t value) :
    Location(Type::ADDRESS),
    address(value) {}

  static bool classof(const Location* loc) {
    return loc->type == Type::ADDRESS;
  }

  ~AddressLoc() override;

  /// Memory address where the value is located
  uint64_t address = 0;
};

/// The value is located in memory relative to the (stack) frame base.
class LIEF_API FrameBaseLoc : public Location {
  public:
  explicit FrameBaseLoc(int64_t value) :
    Location(Type::FRAME_BASE),
    offset(value) {}

  static bool classof(const Location* loc) {
    return loc->type == Type::FRAME_BASE;
  }

  ~FrameBaseLoc() override;

  /// Signed byte offset from the frame base
  int64_t offset = 0;
};

/// The value is located in memory at the address stored in a register plus a
/// signed offset (e.g. `DW_OP_breg7 +8`)
class LIEF_API RegisterOffsetLoc : public Location {
  public:
  RegisterOffsetLoc(uint64_t reg_id, int64_t value) :
    Location(Type::REGISTER_OFFSET),
    id(reg_id),
    offset(value) {}

  static bool classof(const Location* loc) {
    return loc->type == Type::REGISTER_OFFSET;
  }

  ~RegisterOffsetLoc() override;

  /// DWARF id of the register that contains the base address
  uint64_t id = 0;

  /// Signed byte offset added to the register's value
  int64_t offset = 0;
};

/// A DWARF expression that is not evaluated by LIEF: implicit values,
/// computed addresses, entry values, ...
class LIEF_API ExpressionLoc : public Location {
  public:
  ExpressionLoc(std::vector<uint8_t> bytes, std::string text) :
    Location(Type::EXPRESSION),
    expression(std::move(bytes)),
    description(std::move(text)) {}

  static bool classof(const Location* loc) {
    return loc->type == Type::EXPRESSION;
  }

  ~ExpressionLoc() override;

  /// Raw bytes of the DWARF expression
  std::vector<uint8_t> expression;

  /// Textual representation of the expression
  /// (e.g. `DW_OP_lit0, DW_OP_stack_value`)
  std::string description;
};

/// The value is not available at this location (e.g. optimized out)
class LIEF_API UnavailableLoc : public Location {
  public:
  UnavailableLoc() :
    Location(Type::UNAVAILABLE) {}

  static bool classof(const Location* loc) {
    return loc->type == Type::UNAVAILABLE;
  }

  ~UnavailableLoc() override;
};

/// The value is split into several pieces (`DW_OP_piece/DW_OP_bit_piece`),
/// each one with its own location.
///
/// For instance, a 16-bytes structure passed in the `rdi` and `rsi` registers
/// is described with two 8-bytes pieces.
class LIEF_API CompositeLocation : public Location {
  public:
  /// A piece of a composite location
  struct LIEF_API Piece {
    enum class KIND : uint8_t {
      BYTE = 0, ///< `DW_OP_piece`
      BIT,      ///< `DW_OP_bit_piece`
    };

    /// Whether this piece comes from `DW_OP_piece` or `DW_OP_bit_piece`
    KIND kind = KIND::BYTE;

    /// Size of this piece in bits
    uint64_t bit_size = 0;

    /// Offset (in bits) of this piece within the whole value
    uint64_t bit_offset = 0;

    /// For a `DW_OP_bit_piece`, the offset (in bits) of this piece within its
    /// location (e.g. the register)
    std::optional<uint64_t> source_bit_offset;

    /// Location of this piece or a nullptr if it can't be decoded
    std::unique_ptr<Location> location;
  };

  CompositeLocation() :
    Location(Type::COMPOSITE) {}

  CompositeLocation(const CompositeLocation&) = delete;
  CompositeLocation& operator=(const CompositeLocation&) = delete;

  CompositeLocation(CompositeLocation&&) noexcept = default;
  CompositeLocation& operator=(CompositeLocation&&) noexcept = default;

  static bool classof(const Location* loc) {
    return loc->type == Type::COMPOSITE;
  }

  ~CompositeLocation() override;

  /// The pieces of this location, ordered by their bit offset
  std::vector<Piece> pieces;
};

/// Location associated with the range of addresses where it is valid.
struct LIEF_API LocationEntry {
  /// Range of addresses `[low, high)` where the location is valid.
  std::optional<range_t> range;

  /// Index of the object's section containing the range (if any)
  std::optional<uint64_t> section_index;

  /// The location or a nullptr if the DWARF expression can't be decoded
  std::unique_ptr<Location> location;

  /// Human-readable description of this entry
  /// (e.g. `[0x1130, 0x1136): register 5`)
  std::string to_string() const;

  friend std::ostream& operator<<(std::ostream& os, const LocationEntry& entry) {
    os << entry.to_string();
    return os;
  }
};

}

#endif
