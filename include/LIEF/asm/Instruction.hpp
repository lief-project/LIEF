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
#ifndef LIEF_ASM_INST_H
#define LIEF_ASM_INST_H
#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"

#include <ostream>
#include <memory>
#include <string>

namespace LIEF {
namespace assembly {

namespace details {
class Instruction;
class InstructionIt;
}

/// This class represents an assembly instruction
class LIEF_API Instruction {
  public:
  /// **Lazy-forward** iterator that outputs Instruction
  class Iterator final :
    public iterator_facade_base<Iterator, std::forward_iterator_tag, std::unique_ptr<Instruction>,
                                std::ptrdiff_t, Instruction*, std::unique_ptr<Instruction>>
  {
    public:
    using implementation = details::InstructionIt;

    LIEF_API Iterator();

    LIEF_API Iterator(std::unique_ptr<details::InstructionIt> impl);
    LIEF_API Iterator(const Iterator&);
    LIEF_API Iterator& operator=(const Iterator&);

    LIEF_API Iterator(Iterator&&) noexcept;
    LIEF_API Iterator& operator=(Iterator&&) noexcept;

    LIEF_API ~Iterator();

    LIEF_API Iterator& operator++();

    friend LIEF_API bool operator==(const Iterator& LHS, const Iterator& RHS);

    friend bool operator!=(const Iterator& LHS, const Iterator& RHS) {
      return !(LHS == RHS);
    }

    /// Disassemble and output an Instruction at the current iterator's
    /// position.
    LIEF_API std::unique_ptr<Instruction> operator*() const;

    private:
    std::unique_ptr<details::InstructionIt> impl_;
  };
  public:
  /// Address of the instruction
  uint64_t address() const;

  /// Size of the instruction in bytes
  size_t size() const;

  /// Raw bytes of the current instruction
  const std::vector<uint8_t>& raw() const;

  /// Instruction mnemonic (e.g. `br`)
  std::string mnemonic() const;

  /// Representation of the current instruction in a pretty assembly way
  std::string to_string(bool with_address = true) const;

  /// True if the instruction is a call
  bool is_call() const;

  /// True if the instruction marks the end of a basic block
  bool is_terminator() const;

  /// True if the instruction is a branch
  bool is_branch() const;

  /// True if the instruction is a syscall
  bool is_syscall() const;

  /// This function can be used to **down cast** an Instruction instance:
  ///
  /// ```cpp
  /// std::unique_ptr<assembly::Instruction> inst = get_inst();
  /// if (const auto* arm = inst->as<assembly::arm::Instruction>()) {
  ///   const arm::OPCODE op = arm->opcode();
  /// }
  /// ```
  template<class T>
  const T* as() const {
    static_assert(std::is_base_of<Instruction, T>::value,
                  "Require Instruction inheritance");
    if (T::classof(this)) {
      return static_cast<const T*>(this);
    }
    return nullptr;
  }

  friend LIEF_API std::ostream& operator<<(std::ostream& os, const Instruction& inst) {
    os << inst.to_string();
    return os;
  }

  virtual ~Instruction();

  /// \private
  static LIEF_LOCAL std::unique_ptr<Instruction>
    create(std::unique_ptr<details::Instruction> impl);

  /// \private
  LIEF_LOCAL const details::Instruction& impl() const {
    assert(impl_ != nullptr);
    return *impl_;
  }

  /// \private
  LIEF_LOCAL details::Instruction& impl() {
    assert(impl_ != nullptr);
    return *impl_;
  }

  protected:
  LIEF_LOCAL Instruction(std::unique_ptr<details::Instruction> impl);
  std::unique_ptr<details::Instruction> impl_;
};
}
}
#endif
