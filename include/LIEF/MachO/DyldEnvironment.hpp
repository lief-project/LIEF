/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include <iostream>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/LoadCommand.hpp"


namespace LIEF {
namespace MachO {
class LIEF_API DyldEnvironment : public LoadCommand {
  public:
  DyldEnvironment(void);
  DyldEnvironment(const dylinker_command *cmd);

  DyldEnvironment& operator=(const DyldEnvironment& copy);
  DyldEnvironment(const DyldEnvironment& copy);

  virtual ~DyldEnvironment(void);

  virtual std::ostream& print(std::ostream& os) const override;

  const std::string& value(void) const;

  void value(const std::string& values);

  bool operator==(const DyldEnvironment& rhs) const;
  bool operator!=(const DyldEnvironment& rhs) const;

  virtual void accept(Visitor& visitor) const override;


  private:
  std::string value_;
};

}
}
#endif
