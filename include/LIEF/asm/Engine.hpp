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
#ifndef LIEF_ASM_ENGINE_H
#define LIEF_ASM_ENGINE_H
#include "LIEF/compiler_attributes.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/visibility.h"

#include "LIEF/asm/AssemblerConfig.hpp"
#include "LIEF/asm/Instruction.hpp"

#include <string_view>
#include <memory>

namespace LIEF {
class Binary;

/// Namespace related to assembly/disassembly support
namespace assembly {

namespace details {
class Engine;
}

/// This class interfaces the assembler/disassembler support
class LIEF_API Engine {
  public:
  /// Disassembly instruction iterator
  using instructions_it = iterator_range<Instruction::Iterator>;

  Engine() = delete;
  Engine(std::unique_ptr<details::Engine> impl);

  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  Engine(Engine&&) noexcept;
  Engine& operator=(Engine&&) noexcept;

  /// Disassemble the provided buffer with the address specified in the second
  /// parameter.
  /// The engine and the buffer must outlive the returned iterator.
  instructions_it disassemble(const uint8_t* buffer LIEF_LIFETIMEBOUND,
                              size_t size, uint64_t addr) LIEF_LIFETIMEBOUND;

  /// Disassemble the given vector of bytes with the address specified in the
  /// second parameter.
  instructions_it disassemble(const std::vector<uint8_t>& bytes LIEF_LIFETIMEBOUND,
                              uint64_t addr) LIEF_LIFETIMEBOUND {
    return disassemble(bytes.data(), bytes.size(), addr);
  }

  std::vector<uint8_t>
      assemble(uint64_t address, std::string_view Asm,
               AssemblerConfig& config = AssemblerConfig::default_config());

  std::vector<uint8_t>
      assemble(uint64_t address, std::string_view Asm, LIEF::Binary& bin,
               AssemblerConfig& config = AssemblerConfig::default_config());

  std::vector<uint8_t> assemble(const llvm::MCInst& inst);

  std::vector<uint8_t> assemble(const std::vector<llvm::MCInst>& inst);

  ~Engine();

  /// @private
  LIEF_LOCAL const details::Engine& impl() const LIEF_LIFETIMEBOUND {
    assert(impl_ != nullptr);
    return *impl_;
  }

  /// @private
  LIEF_LOCAL details::Engine& impl() LIEF_LIFETIMEBOUND {
    assert(impl_ != nullptr);
    return *impl_;
  }

  private:
  std::unique_ptr<details::Engine> impl_;
};
}
}

#endif
