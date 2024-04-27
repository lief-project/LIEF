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
#include <cstdint>

#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/rust/PE/ResourceNode.hpp"

class PE_ResourceDirectory : public PE_ResourceNode {
  public:
  using lief_t = LIEF::PE::ResourceDirectory;
  PE_ResourceDirectory(const lief_t& obj) : PE_ResourceNode(obj) {}

  uint32_t characteristics() const { return impl().characteristics(); }
  uint32_t time_date_stamp() const { return impl().time_date_stamp(); }
  uint32_t major_version() const { return impl().major_version(); }
  uint32_t minor_version() const { return impl().minor_version(); }
  uint32_t numberof_name_entries() const { return impl().numberof_name_entries(); }
  uint32_t numberof_id_entries() const { return impl().numberof_id_entries(); }

  static bool classof(const PE_ResourceNode& node) {
    return lief_t::classof(&node.get());
  }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
