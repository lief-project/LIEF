/* Copyright 2022 - 2026 R. Thomas
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
    to_vector(const LIEF::pdb::BuildMetadata::version_t& v) {
  return {v.major, v.minor, v.build, v.qfe};
}


inline std::vector<std::string>
    to_vector(LIEF::pdb::BuildMetadata::build_info_t v) {
  return {std::move(v.cwd), std::move(v.build_tool), std::move(v.source_file),
          std::move(v.pdb), std::move(v.command_line)};
}
}

class PDB_BuildMetadata : private Mirror<LIEF::pdb::BuildMetadata> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::pdb::BuildMetadata;

  auto frontend_version() const {
    return make_unique_vector<uint16_t>(
        details::to_vector(get().frontend_version())
    );
  }

  auto backend_version() const {
    return make_unique_vector<uint16_t>(
        details::to_vector(get().backend_version())
    );
  }

  auto version() const {
    return to_unique_string(get().version());
  }

  auto language() const {
    return as_u8(get().language());
  }
  auto target_cpu() const {
    return as_u16(get().target_cpu());
  }

  auto env() const {
    return make_unique_vector<std::string>(get().env());
  }

  auto build_info() const {
    if (auto opt = get().build_info()) {
      return make_unique_vector<std::string>(details::to_vector(std::move(*opt)));
    }
    return make_unique_vector<std::string>();
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};
