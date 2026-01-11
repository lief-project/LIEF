/* Copyright 2024 - 2026 R. Thomas
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
#include <cstdint>

#include "LIEF/COFF/Binary.hpp"
#include "LIEF/COFF/Parser.hpp"

#include "LIEF/rust/COFF/Relocation.hpp"
#include "LIEF/rust/COFF/Symbol.hpp"
#include "LIEF/rust/COFF/String.hpp"
#include "LIEF/rust/COFF/Section.hpp"
#include "LIEF/rust/COFF/Header.hpp"

#include "LIEF/rust/asm/Instruction.hpp"

#include "LIEF/rust/Mirror.hpp"

class COFF_Binary : Mirror<LIEF::COFF::Binary> {
  public:
  using lief_t = LIEF::COFF::Binary;
  using Mirror::Mirror;

  class it_relocations :
      public Iterator<COFF_Relocation, LIEF::COFF::Binary::it_const_relocations>
  {
    public:
    it_relocations(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols :
      public Iterator<COFF_Symbol, LIEF::COFF::Binary::it_const_symbols>
  {
    public:
    it_symbols(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.symbols())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_sections :
      public Iterator<COFF_Section, LIEF::COFF::Binary::it_const_sections>
  {
    public:
    it_sections(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_strings :
      public Iterator<COFF_String, LIEF::COFF::Binary::it_const_strings_table>
  {
    public:
    it_strings(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.string_table())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_functions :
      public Iterator<COFF_Symbol, LIEF::COFF::Binary::it_const_function>
  {
    public:
    it_functions(const COFF_Binary::lief_t& src)
      : Iterator(std::move(src.functions())) { } // NOLINT(performance-move-const-arg)
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_instructions :
      public ForwardIterator<asm_Instruction, LIEF::assembly::Instruction::Iterator>
  {
    public:
    it_instructions(const COFF_Binary::lief_t& src, const std::string& func)
      : ForwardIterator(src.disassemble(func)) { }

    it_instructions(const COFF_Binary::lief_t& src, const LIEF::COFF::Symbol& sym)
      : ForwardIterator(src.disassemble(sym)) { }

    it_instructions(const COFF_Binary::lief_t& src, const uint8_t* ptr,
                    size_t size, uint64_t address)
      : ForwardIterator(src.disassemble(ptr, size, address)) { }

    auto next() { return ForwardIterator::next(); }
  };

  static auto parse(std::string path) { // NOLINT(performance-unnecessary-value-param)
    return details::try_unique<COFF_Binary>(LIEF::COFF::Parser::parse(path));
  }

  auto header() const {
    return std::make_unique<COFF_Header>(get().header());
  }

  auto sections() const {
    return std::make_unique<it_sections>(get());
  }

  auto symbols() const {
    return std::make_unique<it_symbols>(get());
  }

  auto relocations() const {
    return std::make_unique<it_relocations>(get());
  }

  auto string_table() const {
    return std::make_unique<it_strings>(get());
  }

  auto find_string(uint32_t offset) const {
    return details::try_unique<COFF_String>(get().find_string(offset));
  }

  auto find_function(std::string name) const {
    return details::try_unique<COFF_Symbol>(get().find_function(name));
  }

  auto find_demangled_function(std::string name) const {
    return details::try_unique<COFF_Symbol>(get().find_demangled_function(name));
  }

  auto functions() const {
    return std::make_unique<it_functions>(get());
  }

  auto disassemble_buffer(const uint8_t* ptr, uint64_t size, uint64_t addr) const {
    return std::make_unique<it_instructions>(get(), ptr, size, addr);
  }

  auto disassemble_function(std::string function) const {
    return std::make_unique<it_instructions>(get(), function);
  }

  auto disassemble_symbol(const COFF_Symbol& sym) const {
    return std::make_unique<it_instructions>(get(),
        static_cast<const COFF_Symbol::lief_t&>(sym.get()));
  }

  auto to_string() const {
    return get().to_string();
  }
};

