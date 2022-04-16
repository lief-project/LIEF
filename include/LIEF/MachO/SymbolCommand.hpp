/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_MACHO_SYMBOL_COMMAND_H_
#define LIEF_MACHO_SYMBOL_COMMAND_H_
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/span.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {
class BinaryParser;
class LinkEdit;

namespace details {
struct symtab_command;
}

//! Class that represents the LC_SYMTAB command
class LIEF_API SymbolCommand : public LoadCommand {
  friend class BinaryParser;
  friend class LinkEdit;

  public:
  SymbolCommand();
  SymbolCommand(const details::symtab_command& command);

  SymbolCommand& operator=(const SymbolCommand& copy);
  SymbolCommand(const SymbolCommand& copy);

  SymbolCommand* clone() const override;

  virtual ~SymbolCommand();

  //! Offset from the start of the file to the n_list associated with the command
  uint32_t symbol_offset() const;

  //! Number of symbols registered
  uint32_t numberof_symbols() const;

  //! Offset from the start of the file to the string table
  uint32_t strings_offset() const;

  //! Size of the size string table
  uint32_t strings_size() const;

  void symbol_offset(uint32_t offset);
  void numberof_symbols(uint32_t nb);
  void strings_offset(uint32_t offset);
  void strings_size(uint32_t size);


  inline span<const uint8_t> symbol_table() const {
    return symbol_table_;
  }

  inline span<uint8_t> symbol_table() {
    return symbol_table_;
  }

  inline span<const uint8_t> string_table() const {
    return string_table_;
  }

  inline span<uint8_t> string_table() {
    return string_table_;
  }

  inline uint32_t original_str_size() const {
    return original_str_size_;
  }

  inline uint32_t original_nb_symbols() const {
    return original_nb_symbols_;
  }

  std::ostream& print(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  bool operator==(const SymbolCommand& rhs) const;
  bool operator!=(const SymbolCommand& rhs) const;

  static bool classof(const LoadCommand* cmd);

  private:
  uint32_t symbols_offset_ = 0;
  uint32_t nb_symbols_     = 0;
  uint32_t strings_offset_ = 0;
  uint32_t strings_size_   = 0;

  uint32_t original_str_size_   = 0;
  uint32_t original_nb_symbols_ = 0;

  span<uint8_t> symbol_table_;
  span<uint8_t> string_table_;
};

}
}
#endif
