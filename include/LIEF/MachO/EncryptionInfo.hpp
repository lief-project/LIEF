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
#ifndef LIEF_MACHO_ENCRYPTION_INFO_COMMAND_H_
#define LIEF_MACHO_ENCRYPTION_INFO_COMMAND_H_
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct encryption_info_command;
}

//! Class that represents the LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 commands
//!
//! The encryption info is usually present in Mach-O executables that
//! target iOS to encrypt some sections of the binary
class LIEF_API EncryptionInfo : public LoadCommand {
  public:
  EncryptionInfo();
  EncryptionInfo(const details::encryption_info_command& cmd);

  EncryptionInfo& operator=(const EncryptionInfo& copy);
  EncryptionInfo(const EncryptionInfo& copy);

  virtual ~EncryptionInfo();

  //! The beginning of the encrypted area
  uint32_t crypt_offset() const;

  //! The size of the encrypted area
  uint32_t crypt_size() const;

  //! The encryption system. 0 means no encrypted
  uint32_t crypt_id() const;

  void crypt_offset(uint32_t offset);
  void crypt_size(uint32_t size);
  void crypt_id(uint32_t id);

  bool operator==(const EncryptionInfo& rhs) const;
  bool operator!=(const EncryptionInfo& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  uint32_t coff_;
  uint32_t csize_;
  uint32_t cid_;
};

}
}
#endif
