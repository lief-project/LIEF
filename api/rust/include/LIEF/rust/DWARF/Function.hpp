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
#include "LIEF/DWARF/Function.hpp"
#include "LIEF/rust/DWARF/Variable.hpp"
#include "LIEF/rust/DWARF/Scope.hpp"
#include "LIEF/rust/DWARF/Type.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/range.hpp"
#include "LIEF/rust/debug_location.hpp"
#include "LIEF/rust/error.hpp"

class DWARF_Function_Parameter : private Mirror<LIEF::dwarf::Function::Parameter> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Function;

  auto name() const { return get().name(); }

  auto get_type() const {
    return details::try_unique<DWARF_Type>(get().type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};

class DWARF_Function : private Mirror<LIEF::dwarf::Function> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::Function;

  class it_variables :
      public ForwardIterator<DWARF_Variable, LIEF::dwarf::Variable::Iterator>
  {
    public:
    it_variables(const DWARF_Function::lief_t& src)
      : ForwardIterator(src.variables()) { }
    auto next() { return ForwardIterator::next(); }
  };

  class it_parameters :
      public ContainerIterator<DWARF_Function_Parameter,
                             std::vector<LIEF::dwarf::Function::Parameter>>
  {
    public:
    using container_t = std::vector<LIEF::dwarf::Function::Parameter>;
    it_parameters(container_t content)
      : ContainerIterator(std::move(content)) { }
    auto next() { return ContainerIterator::next(); }
  };

  auto name() const { return get().name(); }
  auto linkage_name() const { return get().linkage_name(); }

  auto variables() const {
    return std::make_unique<it_variables>(get());
  }

  uint64_t address(uint32_t& err) const {
    return details::make_error<uint64_t>(
        get().address(), err
    );
  }

  auto is_artificial() const { return get().is_artificial(); }
  auto size() const { return get().size(); }
  auto ranges() const { return details::make_range(get().ranges()); }
  auto debug_location() const { return details::make_location(get().debug_location()); }

  auto get_type() const {
    return details::try_unique<DWARF_Type>(get().type()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto parameters() const {
    std::vector<LIEF::dwarf::Function::Parameter> params = get().parameters();
    return std::make_unique<it_parameters>(std::move(params));
  }

  auto scope() const {
    return details::try_unique<DWARF_Scope>(get().scope()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};
