/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_ELF_SYMBOL_VERSION_H
#define LIEF_ELF_SYMBOL_VERSION_H
#include <cassert>
#include <cstdint>
#include <ostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"


namespace LIEF::ELF {
class Parser;
class SymbolVersionAux;
class SymbolVersionAuxRequirement;

/// Class which represents an entry defined in the `DT_VERSYM`
/// dynamic entry
class LIEF_API SymbolVersion : public Object {
  friend class Parser;

  public:
  static constexpr uint16_t LOCAL_VERSION = 0;
  static constexpr uint16_t GLOBAL_VERSION = 1;

  /// Mask for the GNU `VERSYM_HIDDEN` bit.
  static constexpr uint16_t HIDDEN_MASK = 0x8000;

  /// Mask for the version index (`VERSYM_VERSION` in the GNU implementation).
  static constexpr uint16_t VERSION_MASK = 0x7fff;

  SymbolVersion(uint16_t value) :
    value_(value) {}
  SymbolVersion() = default;

  /// Generate a *local* SymbolVersion
  static SymbolVersion local() {
    return LOCAL_VERSION;
  }

  /// Generate a *global* SymbolVersion
  static SymbolVersion global() {
    return GLOBAL_VERSION;
  }

  ~SymbolVersion() override = default;

  SymbolVersion& operator=(const SymbolVersion&) = default;
  SymbolVersion(const SymbolVersion&) = default;

  /// Value associated with the symbol
  ///
  /// If the given SymbolVersion hasn't Auxiliary version:
  ///
  /// * ``0`` means **Local**
  /// * ``1`` means **Global**
  uint16_t value() const {
    return value_;
  }

  /// Version index without the GNU `VERSYM_HIDDEN` bit.
  uint16_t version() const {
    return value() & VERSION_MASK;
  }

  /// Whether this symbol version is local (`VER_NDX_LOCAL`).
  bool is_local() const {
    return version() == LOCAL_VERSION;
  }

  /// Whether this symbol version is global (`VER_NDX_GLOBAL`).
  ///
  /// `VERSYM_BASE` has the same value as `VER_NDX_GLOBAL`, so this also
  /// identifies the base version.
  bool is_global() const {
    return version() == GLOBAL_VERSION;
  }

  /// Whether the GNU `VERSYM_HIDDEN` bit is set.
  ///
  /// A hidden version is only available when explicitly referenced by its
  /// version name.
  bool is_hidden() const {
    return (value() & HIDDEN_MASK) != 0;
  }

  /// Set or clear the GNU `VERSYM_HIDDEN` bit while preserving the version
  /// index.
  void set_hidden(bool value = true) {
    if (value) {
      value_ |= HIDDEN_MASK;
    } else {
      value_ &= VERSION_MASK;
    }
  }

  /// Whether the current SymbolVersion has an auxiliary one
  bool has_auxiliary_version() const {
    return symbol_version_auxiliary() != nullptr;
  }

  /// SymbolVersionAux associated with the current Version if any,
  /// or a nullptr
  SymbolVersionAux* symbol_version_auxiliary() LIEF_LIFETIMEBOUND {
    return symbol_aux_;
  }

  const SymbolVersionAux* symbol_version_auxiliary() const LIEF_LIFETIMEBOUND {
    return symbol_aux_;
  }

  /// Set the version's auxiliary requirement
  /// The given SymbolVersionAuxRequirement must be an existing
  /// reference in the ELF::Binary.
  ///
  /// On can add a new SymbolVersionAuxRequirement by using
  /// SymbolVersionRequirement::add_aux_requirement
  void symbol_version_auxiliary(SymbolVersionAuxRequirement& svauxr);

  /// Drop the versioning requirement and replace the value (local/global)
  void drop_version(uint16_t value) {
    assert(value == LOCAL_VERSION || value == GLOBAL_VERSION);
    value_ = value;
    symbol_aux_ = nullptr;
  }

  /// Redefine this version as global by dropping its auxiliary version
  ///
  /// @see as_local() drop_version()
  void as_global() {
    return drop_version(GLOBAL_VERSION);
  }

  /// Redefine this version as local by dropping its auxiliary version
  ///
  /// @see as_global() drop_version()
  void as_local() {
    return drop_version(LOCAL_VERSION);
  }

  void value(uint16_t v) {
    value_ = v;
  }

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const SymbolVersion& symv);

  private:
  uint16_t value_ = 0;
  SymbolVersionAux* symbol_aux_ = nullptr;
};
}

#endif
