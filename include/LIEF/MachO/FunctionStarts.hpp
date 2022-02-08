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
#ifndef LIEF_MACHO_FUNCTION_STARTS_COMMAND_H_
#define LIEF_MACHO_FUNCTION_STARTS_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct linkedit_data_command;
}


//! Class which represents the LC_FUNCTION_STARTS command
//!
//! This command is an array of ULEB128 encoded values
class LIEF_API FunctionStarts : public LoadCommand {
  public:
  FunctionStarts();
  FunctionStarts(const details::linkedit_data_command& cmd);

  FunctionStarts& operator=(const FunctionStarts& copy);
  FunctionStarts(const FunctionStarts& copy);

  FunctionStarts* clone() const override;

  //! Offset in the ``__LINKEDIT`` SegmentCommand where *start functions* are located
  uint32_t data_offset() const;

  //! Size of the functions list in the binary
  uint32_t data_size() const;

  //! Addresses of every function entry point in the executable.
  //!
  //! This allows functions to exist for which there are no entries in the symbol table.
  //!
  //! @warning The address is relative to the ``__TEXT`` segment
  const std::vector<uint64_t>& functions() const;

  std::vector<uint64_t>& functions();

  //! Add a new function
  void add_function(uint64_t address);

  void data_offset(uint32_t offset);
  void data_size(uint32_t size);
  void functions(const std::vector<uint64_t>& funcs);

  virtual ~FunctionStarts();

  bool operator==(const FunctionStarts& rhs) const;
  bool operator!=(const FunctionStarts& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  uint32_t data_offset_;
  uint32_t data_size_;
  std::vector<uint64_t> functions_;
};

}
}
#endif
