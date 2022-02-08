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
#ifndef LIEF_MACHO_FILESET_COMMAND_H_
#define LIEF_MACHO_FILESET_COMMAND_H_
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/types.hpp"
#include "LIEF/MachO/LoadCommand.hpp"


namespace LIEF {
namespace MachO {
class Binary;
class BinaryParser;

namespace details {
struct fileset_entry_command;
}

//! Class associated with the LC_FILESET_ENTRY commands
class LIEF_API FilesetCommand : public LoadCommand {
  public:
  friend class BinaryParser;
  using content_t = std::vector<uint8_t>;

  FilesetCommand();
  FilesetCommand(const details::fileset_entry_command& command);
  FilesetCommand(const std::string& name);

  FilesetCommand& operator=(FilesetCommand copy);
  FilesetCommand(const FilesetCommand& copy);

  void swap(FilesetCommand& other);

  FilesetCommand* clone() const override;

  virtual ~FilesetCommand();

  //! Name of the underlying MachO binary (e.g. ``com.apple.security.quarantine``)
  const std::string& name() const;

  //! Memory address where the MachO file should be mapped
  uint64_t virtual_address() const;

  //! Original offset in the kernel cache
  uint64_t file_offset() const;

  //! Return a pointer on the LIEF::MachO::Binary associated
  //! with this entry
  inline const Binary* binary() const {
    return binary_;
  }

  inline Binary* binary() {
    return binary_;
  }

  void name(const std::string& name);
  void virtual_address(uint64_t virtual_address);
  void file_offset(uint64_t file_offset);

  std::ostream& print(std::ostream& os) const override;

  bool operator==(const FilesetCommand& rhs) const;
  bool operator!=(const FilesetCommand& rhs) const;

  static bool classof(const LoadCommand* cmd);

  private:
  std::string name_;
  uint64_t virtual_address_{0};
  uint64_t file_offset_{0};
  Binary* binary_ = nullptr;
};

}
}
#endif
