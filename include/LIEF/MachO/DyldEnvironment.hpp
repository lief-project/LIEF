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
#ifndef LIEF_MACHO_DYLD_ENVIROMENT_COMMAND_H_
#define LIEF_MACHO_DYLD_ENVIROMENT_COMMAND_H_
#include <string>
#include <iostream>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct dylinker_command;
}

//! Class that represents a LC_DYLD_ENVIRONMENT which is
//! used by the Mach-O linker/loader to initialize an environment variable
class LIEF_API DyldEnvironment : public LoadCommand {
  public:
  DyldEnvironment();
  DyldEnvironment(const details::dylinker_command& cmd);

  DyldEnvironment& operator=(const DyldEnvironment& copy);
  DyldEnvironment(const DyldEnvironment& copy);

  DyldEnvironment* clone() const override;

  virtual ~DyldEnvironment();

  std::ostream& print(std::ostream& os) const override;

  //! The actual environment variable
  const std::string& value() const;

  void value(const std::string& values);

  bool operator==(const DyldEnvironment& rhs) const;
  bool operator!=(const DyldEnvironment& rhs) const;

  void accept(Visitor& visitor) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  std::string value_;
};

}
}
#endif
