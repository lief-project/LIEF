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
#include "LIEF/rust/Abstract/DebugInfo.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/PDB/CompilationUnit.hpp"
#include "LIEF/rust/PDB/PublicSymbol.hpp"
#include "LIEF/rust/PDB/Type.hpp"

#include "LIEF/PDB/DebugInfo.hpp"
#include "LIEF/PDB/CompilationUnit.hpp"

class PDB_DebugInfo : public AbstracDebugInfo {
  public:
  using lief_t = LIEF::pdb::DebugInfo;

  class it_compilation_units :
      public ForwardIterator<PDB_CompilationUnit, LIEF::pdb::CompilationUnit::Iterator>
  {
    public:
    it_compilation_units(const PDB_DebugInfo::lief_t& src)
      : ForwardIterator(src.compilation_units()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_public_symbols :
      public ForwardIterator<PDB_PublicSymbol, LIEF::pdb::PublicSymbol::Iterator>
  {
    public:
    it_public_symbols(const PDB_DebugInfo::lief_t& src)
      : ForwardIterator(src.public_symbols()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_types :
      public ForwardIterator<PDB_Type, LIEF::pdb::Type::Iterator>
  {
    public:
    it_types(const PDB_DebugInfo::lief_t& src)
      : ForwardIterator(src.types()) { }
    auto next() { return ForwardIterator::next(); }
  };

  PDB_DebugInfo(std::unique_ptr<lief_t> bin) : AbstracDebugInfo(std::move(bin)) {}

  static auto from_file(std::string file) { // NOLINT(performance-unnecessary-value-param)
    return std::make_unique<PDB_DebugInfo>(LIEF::pdb::DebugInfo::from_file(file));
  }

  auto age() const { return impl().age(); }
  auto guid() const { return impl().guid(); }

  auto compilation_units() const {
    return std::make_unique<it_compilation_units>(impl());
  }

  auto public_symbols() const {
    return std::make_unique<it_public_symbols>(impl());
  }

  auto types() const {
    return std::make_unique<it_types>(impl());
  }

  auto public_symbol_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PDB_PublicSymbol>(impl().find_public_symbol(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto find_type(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<PDB_Type>(impl().find_type(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  static bool classof(const AbstracDebugInfo& reloc) {
    return lief_t::classof(static_cast<const AbstracDebugInfo::lief_t*>(&reloc.get()));
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
