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
#ifndef LIEF_MACHO_MAIN_COMMAND_H_
#define LIEF_MACHO_MAIN_COMMAND_H_
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/MachO/enums.hpp"
#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct entry_point_command;
}

//! Class that represent the LC_MAIN command. This kind
//! of command can be used to determine the entrypoint of an executable
class LIEF_API MainCommand : public LoadCommand {
  public:
  MainCommand();
  MainCommand(const details::entry_point_command& cmd);

  MainCommand& operator=(const MainCommand& copy);
  MainCommand(const MainCommand& copy);

  MainCommand* clone() const override;

  virtual ~MainCommand();

  //! Offset of the *main* function relative to the ``__TEXT``
  //! segment
  uint64_t entrypoint() const;

  //! The initial stack size (if not 0)
  uint64_t stack_size() const;

  void entrypoint(uint64_t entrypoint);
  void stack_size(uint64_t stacksize);

  bool operator==(const MainCommand& rhs) const;
  bool operator!=(const MainCommand& rhs) const;

  std::ostream& print(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  uint64_t entrypoint_ = 0;
  uint64_t stack_size_ = 0;
};

}
}
#endif
