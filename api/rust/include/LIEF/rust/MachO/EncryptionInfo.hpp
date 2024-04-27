/* Copyright 2024 R. Thomas
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

#pragma once

#include "LIEF/MachO/EncryptionInfo.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_EncryptionInfo : public MachO_Command {
  using lief_t = LIEF::MachO::EncryptionInfo;
  public:
  MachO_EncryptionInfo(const lief_t& base) : MachO_Command(base) {}
  uint32_t crypt_offset() const { return impl().crypt_offset(); };
  uint32_t crypt_size() const { return impl().crypt_size(); };
  uint32_t crypt_id() const { return impl().crypt_id(); };

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
