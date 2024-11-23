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

    LIEF_API std::unique_ptr<Instruction> operator*() const;

    private:
    std::unique_ptr<details::InstructionIt> impl_;
  };
  public:

  /// \private
  static LIEF_LOCAL std::unique_ptr<Instruction>
    create(std::unique_ptr<details::Instruction> impl);

  virtual ~Instruction();

  /// Address of the instruction
  uint64_t address() const;

  /// Size of the instruction in bytes
  size_t size() const;

  /// Raw bytes of the current instruction
  const std::vector<uint8_t>& raw() const;

  /// Instruction mnemonic (e.g. `br`)
  std::string mnemonic() const;

  /// Representation of the current instruction in a pretty assembly way
  std::string to_string() const;

  friend LIEF_API std::ostream& operator<<(std::ostream& os, const Instruction& inst) {
    os << inst.to_string();
    return os;
  }

  protected:
  Instruction(std::unique_ptr<details::Instruction> impl);
  std::unique_ptr<details::Instruction> impl_;
};
}
}
#endif
