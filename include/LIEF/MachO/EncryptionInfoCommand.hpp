/* Copyright 2017 Zhang
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
#ifndef LIEF_MACHO_ENCRYPTION_INFO__H_
#define LIEF_MACHO_ENCRYPTION_INFO__H_

#include <iostream>
#include <set>
#include <string>

#include "LIEF/visibility.h"
#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/types.hpp"

namespace LIEF {
namespace MachO {

class DLL_PUBLIC EncryptionInfoCommand : public LoadCommand {
  public:
    EncryptionInfoCommand(void);
    EncryptionInfoCommand(const encryption_info_command_32 *cmd);
    EncryptionInfoCommand& operator=(const EncryptionInfoCommand& copy);
    EncryptionInfoCommand(const EncryptionInfoCommand& copy);
    virtual ~EncryptionInfoCommand(void);
    uint32_t crypt_offset(void) const;
    uint32_t crypt_size(void) const;
    uint32_t crypt_id(void) const;

    void crypt_offset(uint32_t offset);
    void crypt_size(uint32_t sz);
    void crypt_id(uint32_t id);
    virtual std::ostream& print(std::ostream& os) const override;

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const EncryptionInfoCommand& rhs) const;
    bool operator!=(const EncryptionInfoCommand& rhs) const;
  private:
    uint32_t crypt_offset_;
    uint32_t crypt_size_;
    uint32_t crypt_id_;
};

}
}
#endif
