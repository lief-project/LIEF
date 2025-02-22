/* Copyright 2022 - 2025 R. Thomas
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

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/PDB/BuildMetadata.hpp"

namespace details {
inline std::vector<uint16_t>
  to_vector(const LIEF::pdb::BuildMetadata::version_t& v)
{
  return {v.major, v.minor, v.build, v.qfe };
}


inline std::vector<std::string>
  to_vector(LIEF::pdb::BuildMetadata::build_info_t v)
{
  return {
    std::move(v.cwd), std::move(v.build_tool), std::move(v.source_file),
    std::move(v.pdb), std::move(v.command_line)
  };
}
}

class PDB_BuildMetadata : private Mirror<LIEF::pdb::BuildMetadata> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::pdb::BuildMetadata;

  auto frontend_version() const {
    return details::to_vector(get().frontend_version());
  }

  auto backend_version() const {
    return details::to_vector(get().backend_version());
  }

  std::string version() const { return get().version(); }

  auto language() const { return to_int(get().language()); }
  auto target_cpu() const { return to_int(get().target_cpu()); }

  auto env() const { return get().env(); }

  auto build_info() const {
    if (auto opt = get().build_info()) {
      return details::to_vector(std::move(*opt));
    }
    return std::vector<std::string>{};
  }

  std::string to_string() const { return get().to_string(); }
};
