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
#include <string>
#include <memory>
#include <LIEF/MachO.hpp>
#include "LIEF/rust/MachO/Binary.hpp"
#include "LIEF/rust/Mirror.hpp"

class MachO_FatBinary : private Mirror<LIEF::MachO::FatBinary> {
  public:
  using Mirror::Mirror;
  static auto parse(std::string path) {
    return details::try_unique<MachO_FatBinary>(LIEF::MachO::Parser::parse(path));
  }

  uint32_t size() const { return get().size(); }

  std::unique_ptr<MachO_Binary> binary_at(uint32_t index) const {
    if (auto* bin = get().at(index)) {
      return std::make_unique<MachO_Binary>(*bin);
    }
    return nullptr;
  }
};
