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
#include "LIEF/DWARF/CompilationUnit.hpp"

#include "LIEF/rust/DWARF/Function.hpp"
#include "LIEF/rust/DWARF/Type.hpp"

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/range.hpp"
#include "LIEF/rust/DebugDeclOpt.hpp"

struct imported_t {};
struct implemented_t {};

class DWARF_CompilationUnit : private Mirror<LIEF::dwarf::CompilationUnit> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::CompilationUnit;

  class it_functions
    : public ForwardIterator<DWARF_Function, LIEF::dwarf::Function::Iterator> {
    public:
    it_functions(const DWARF_CompilationUnit::lief_t& src, implemented_t) :
      ForwardIterator(src.functions()) {}

    it_functions(const DWARF_CompilationUnit::lief_t& src, imported_t) :
      ForwardIterator(src.imported_functions()) {}
    auto next() {
      return ForwardIterator::next();
    }
    auto size() const {
      return ForwardIterator::size();
    }
  };

  class it_types
    : public ForwardIterator<DWARF_Type, LIEF::dwarf::Type::Iterator> {
    public:
    it_types(const DWARF_CompilationUnit::lief_t& src) :
      ForwardIterator(src.types()) {}
    auto next() {
      return ForwardIterator::next();
    }
    auto size() const {
      return ForwardIterator::size();
    }
  };

  class it_variables
    : public ForwardIterator<DWARF_Variable, LIEF::dwarf::Variable::Iterator> {
    public:
    it_variables(const DWARF_CompilationUnit::lief_t& src) :
      ForwardIterator(src.variables()) {}
    auto next() {
      return ForwardIterator::next();
    }
    auto size() const {
      return ForwardIterator::size();
    }
  };

  class Language {
    public:
    uint32_t lang = 0;
    uint32_t version = 0;
  };

  auto name() const {
    return to_unique_string(get().name());
  }
  auto producer() const {
    return to_unique_string(get().producer());
  }
  auto compilation_dir() const {
    return to_unique_string(get().compilation_dir());
  }

  auto low_address() const {
    return get().low_address();
  }
  auto high_address() const {
    return get().high_address();
  }
  auto size() const {
    return get().size();
  }
  auto ranges() const {
    return make_unique_vector<Range>(details::make_range(get().ranges()));
  }

  Language language() const {
    auto lang = get().language();
    return {/*lang=*/to_int(lang.lang),
            /*version=*/lang.version};
  }

  auto function_by_name(const std::string& name) const {
    return details::try_unique<DWARF_Function>(get().find_function(name));
  }

  auto function_by_address(uint64_t addr) const {
    return details::try_unique<DWARF_Function>(get().find_function(addr));
  }

  auto variable_by_name(const std::string& name) const {
    return details::try_unique<DWARF_Variable>(get().find_variable(name));
  }

  auto variable_by_address(uint64_t addr) const {
    return details::try_unique<DWARF_Variable>(
        get().find_variable(addr)
    ); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto functions() const {
    return std::make_unique<it_functions>(get(), implemented_t{});
  }

  auto imported_functions() const {
    return std::make_unique<it_functions>(get(), imported_t{});
  }

  auto types() const {
    return std::make_unique<it_types>(get());
  }

  auto variables() const {
    return std::make_unique<it_variables>(get());
  }

  auto to_decl() const {
    return to_unique_string(get().to_decl());
  }

  auto to_decl_with_opt(const LIEF_DeclOpt& opt) const {
    return to_unique_string(get().to_decl(opt.conf()));
  }
};

using DWARF_CompilationUnit_it_functions = DWARF_CompilationUnit::it_functions;
using DWARF_CompilationUnit_it_types = DWARF_CompilationUnit::it_types;
using DWARF_CompilationUnit_it_variables = DWARF_CompilationUnit::it_variables;
using DWARF_CompilationUnit_Language = DWARF_CompilationUnit::Language;
