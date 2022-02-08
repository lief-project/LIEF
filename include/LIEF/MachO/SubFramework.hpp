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
#ifndef LIEF_MACHO_SUB_FRAMEWORK_H_
#define LIEF_MACHO_SUB_FRAMEWORK_H_
#include <string>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;

namespace details {
struct sub_framework_command;
}

//! Class that represents the SubFramework command.
//! Accodring to the Mach-O ``loader.h`` documentation:
//!
//!
//! > A dynamically linked shared library may be a subframework of an umbrella
//! > framework.  If so it will be linked with "-umbrella umbrella_name" where
//! > Where "umbrella_name" is the name of the umbrella framework. A subframework
//! > can only be linked against by its umbrella framework or other subframeworks
//! > that are part of the same umbrella framework.  Otherwise the static link
//! > editor produces an error and states to link against the umbrella framework.
//! > The name of the umbrella framework for subframeworks is recorded in the
//! > following structure.
class LIEF_API SubFramework : public LoadCommand {
  friend class BinaryParser;
  public:
  SubFramework();
  SubFramework(const details::sub_framework_command& cmd);

  SubFramework& operator=(const SubFramework& copy);
  SubFramework(const SubFramework& copy);

  SubFramework* clone() const override;

  //! Name of the umbrella framework
  const std::string& umbrella() const;
  void umbrella(const std::string& u);

  virtual ~SubFramework();

  bool operator==(const SubFramework& rhs) const;
  bool operator!=(const SubFramework& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  std::string umbrella_;
};

}
}
#endif
