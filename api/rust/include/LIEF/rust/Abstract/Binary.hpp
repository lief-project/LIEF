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
#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/rust/Abstract/DebugInfo.hpp>
#include <LIEF/rust/Mirror.hpp>

class AbstractBinary : public Mirror<LIEF::Binary> {
  public:
  using Mirror::Mirror;

  uint64_t entrypoint() const { return get().entrypoint(); }
  uint64_t imagebase() const { return get().imagebase(); }
  uint64_t original_size() const { return get().original_size(); }
  bool is_pie() const { return get().is_pie(); }
  bool has_nx() const { return get().has_nx(); }

  auto debug_info() const {
    return details::try_unique<AbstracDebugInfo>(get().debug_info()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
  }
};
