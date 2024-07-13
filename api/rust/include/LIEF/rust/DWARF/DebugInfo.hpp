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
#include <LIEF/rust/Abstract/DebugInfo.hpp>
#include <LIEF/rust/DWARF/CompilationUnit.hpp>
#include <LIEF/rust/DWARF/Function.hpp>
#include <LIEF/DWARF/DebugInfo.hpp>

#include "LIEF/rust/Iterator.hpp"

class DWARF_DebugInfo : public AbstracDebugInfo {
  public:
  using lief_t = LIEF::dwarf::DebugInfo;

  class it_compilation_units :
      public ForwardIterator<DWARF_CompilationUnit, LIEF::dwarf::CompilationUnit::Iterator>
  {
    public:
    it_compilation_units(const DWARF_DebugInfo::lief_t& src)
      : ForwardIterator(src.compilation_units()) { }
    auto next() { return ForwardIterator::next(); }
  };

  DWARF_DebugInfo(std::unique_ptr<lief_t> bin) : AbstracDebugInfo(std::move(bin)) {}

  static auto from_file(std::string file) { // NOLINT(performance-unnecessary-value-param)
    return std::make_unique<DWARF_DebugInfo>(LIEF::dwarf::DebugInfo::from_file(file));
  }

  auto compilation_units() const {
    return std::make_unique<it_compilation_units>(impl());
  }

  auto function_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<DWARF_Function>(impl().find_function(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto function_by_addr(uint64_t addr) const {
    return details::try_unique<DWARF_Function>(impl().find_function(addr)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto variable_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<DWARF_Variable>(impl().find_variable(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto variable_by_addr(uint64_t addr) const {
    return details::try_unique<DWARF_Variable>(impl().find_variable(addr)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto type_by_name(std::string name) const { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<DWARF_Type>(impl().find_type(name)); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  static bool classof(const AbstracDebugInfo& reloc) {
    return lief_t::classof(static_cast<const AbstracDebugInfo::lief_t*>(&reloc.get()));
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
