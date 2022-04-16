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
#ifndef LIEF_MACHO_LOAD_COMMAND_H_
#define LIEF_MACHO_LOAD_COMMAND_H_

#include <string>
#include <vector>

#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/enums.hpp"

namespace LIEF {
namespace MachO {
class Builder;
class BinaryParser;

namespace details {
struct load_command;
}

//! Based class for the Mach-O load commands
class LIEF_API LoadCommand : public Object {
  friend class Builder;
  friend class BinaryParser;
  public:
  using raw_t = std::vector<uint8_t>;

  public:
  LoadCommand();
  LoadCommand(const details::load_command& command);
  LoadCommand(LOAD_COMMAND_TYPES type, uint32_t size);

  LoadCommand& operator=(LoadCommand copy);
  LoadCommand(const LoadCommand& copy);

  void swap(LoadCommand& other);
  virtual LoadCommand* clone() const;

  virtual ~LoadCommand();

  //! Command type
  LOAD_COMMAND_TYPES command() const;

  //! Size of the command (should be greather than ``sizeof(load_command)``)
  uint32_t size() const;

  //! Raw command
  const raw_t& data() const;

  //! Offset of the command within the *Load Command Table*
  uint64_t command_offset() const;

  void data(const raw_t& data);
  void command(LOAD_COMMAND_TYPES command);
  void size(uint32_t size);
  void command_offset(uint64_t offset);

  virtual std::ostream& print(std::ostream& os) const;

  bool operator==(const LoadCommand& rhs) const;
  bool operator!=(const LoadCommand& rhs) const;

  void accept(Visitor& visitor) const override;

  static bool is_linkedit_data(const LoadCommand& cmd);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const LoadCommand& cmd);

  protected:
  raw_t original_data_;
  LOAD_COMMAND_TYPES command_;
  uint32_t size_ = 0;
  uint64_t command_offset_ = 0;
};

}
}
#endif
