/* Copyright 2024 R. Thomas
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
#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/rust/Abstract/DebugInfo.hpp>
#include <LIEF/rust/asm/Instruction.hpp>
#include <LIEF/rust/Mirror.hpp>
#include <LIEF/rust/Iterator.hpp>

#include "LIEF/rust/error.hpp"

class AbstractBinary : public Mirror<LIEF::Binary> {
  public:
  using lief_t = LIEF::Binary;
  using Mirror::Mirror;

  class it_instructions :
      public ForwardIterator<asm_Instruction, LIEF::assembly::Instruction::Iterator>
  {
    public:
    it_instructions(const AbstractBinary::lief_t& src, uint64_t addr, size_t size)
      : ForwardIterator(src.disassemble(addr, size)) { }

    it_instructions(const AbstractBinary::lief_t& src, uint64_t addr)
      : ForwardIterator(src.disassemble(addr)) { }

    it_instructions(const AbstractBinary::lief_t& src, const std::string& func)
      : ForwardIterator(src.disassemble(func)) { }

    it_instructions(const AbstractBinary::lief_t& src,
                    const uint8_t* ptr, size_t size,
                    uint64_t address)
      : ForwardIterator(src.disassemble(ptr, size, address)) { }

    auto next() { return ForwardIterator::next(); }
  };

  uint64_t entrypoint() const { return get().entrypoint(); }
  uint64_t imagebase() const { return get().imagebase(); }
  uint64_t original_size() const { return get().original_size(); }
  bool is_pie() const { return get().is_pie(); }
  bool has_nx() const { return get().has_nx(); }

  uint8_t get_u8(uint64_t addr, uint32_t& err) const {
    return details::make_error(get().get_int_from_virtual_address<uint8_t>(addr), err);
  }

  uint16_t get_u16(uint64_t addr, uint32_t& err) const {
    return details::make_error(get().get_int_from_virtual_address<uint16_t>(addr), err);
  }

  uint32_t get_u32(uint64_t addr, uint32_t& err) const {
    return details::make_error(get().get_int_from_virtual_address<uint32_t>(addr), err);
  }

  uint64_t get_u64(uint64_t addr, uint32_t& err) const {
    return details::make_error(get().get_int_from_virtual_address<uint64_t>(addr), err);
  }

  auto debug_info() const {
    return details::try_unique<AbstracDebugInfo>(get().debug_info()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }

  auto disassemble(uint64_t addr, uint64_t size) const {
    return std::make_unique<it_instructions>(get(), addr, size);
  }

  auto disassemble_address(uint64_t addr) const {
    return std::make_unique<it_instructions>(get(), addr);
  }

  auto disassemble_buffer(const uint8_t* ptr, uint64_t size, uint64_t addr) const {
    return std::make_unique<it_instructions>(get(), ptr, size, addr);
  }

  auto disassemble_function(std::string function) const {
    return std::make_unique<it_instructions>(get(), function);
  }

  auto assemble(uint64_t address, std::string Asm) {
    return get().assemble(address, Asm);
  }

};
