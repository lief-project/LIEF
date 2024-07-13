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

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/PDB/Function.hpp"
#include "LIEF/PDB/CompilationUnit.hpp"

class PDB_CompilationUnit : private Mirror<LIEF::pdb::CompilationUnit> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::pdb::CompilationUnit;

  class it_sources :
      public ForwardIterator<std::string, std::vector<std::string>::const_iterator>
  {
    public:
    it_sources(const PDB_CompilationUnit::lief_t& src)
      : ForwardIterator(src.sources()) { }
    std::string next() {
      auto next_string = ForwardIterator::next();
      if (next_string == nullptr) {
        // Not ideal but autocxx is not able to deal with
        // std::unique_ptr<std::string>:
        // "Type std::unique_ptr was parameterized over something complex which we don't yet support"
        return "[LIEF_STOP]";
      }
      return *next_string;
    }
  };

  class it_functions :
      public ForwardIterator<PDB_Function, LIEF::pdb::Function::Iterator>
  {
    public:
    it_functions(const PDB_CompilationUnit::lief_t& src)
      : ForwardIterator(src.functions()) { }
    auto next() { return ForwardIterator::next(); }
  };

  auto module_name() const { return get().module_name(); }
  auto object_filename() const { return get().object_filename(); }

  auto sources() const {
    return std::make_unique<it_sources>(get());
  }

  auto functions() const {
    return std::make_unique<it_functions>(get());
  }
};
