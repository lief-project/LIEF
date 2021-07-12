/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
struct fileset_entry_command;

class LIEF_API FilesetCommand : public LoadCommand {
  public:
  using content_t = std::vector<uint8_t>;

  FilesetCommand(void);
  FilesetCommand(const fileset_entry_command *command);
  FilesetCommand(const std::string& name, const content_t& content);
  FilesetCommand(const std::string& name);

  FilesetCommand& operator=(FilesetCommand copy);
  FilesetCommand(const FilesetCommand& copy);

  void swap(FilesetCommand& other);

  virtual FilesetCommand* clone(void) const override;

  virtual ~FilesetCommand(void);

  const std::string& name(void) const;
  uint64_t virtual_address(void) const;
  uint64_t file_offset(void) const;

  const content_t& content(void) const;

  void name(const std::string& name);
  void virtual_address(uint64_t virtualAddress);
  void file_offset(uint64_t fileOffset);
  void content(const content_t& data);

  virtual std::ostream& print(std::ostream& os) const override;

  bool operator==(const FilesetCommand& rhs) const;
  bool operator!=(const FilesetCommand& rhs) const;

  private:
  std::string name_;
  uint64_t virtualAddress_{0};
  uint64_t fileOffset_{0};
  content_t data_;
};

}
}
#endif
