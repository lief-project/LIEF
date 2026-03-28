/* Copyright 2024 - 2026 R. Thomas
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
#include "LIEF/MachO/utils.hpp"
#include "LIEF/rust/MachO/Binary.hpp"
#include "LIEF/rust/MachO/FatBinary.hpp"

class MachO_Utils {
  public:
  static bool is_macho(std::string file) {
    return LIEF::MachO::is_macho(file);
  }

  static bool is_fat(std::string file) {
    return LIEF::MachO::is_fat(file);
  }

  static bool is_64(std::string file) {
    return LIEF::MachO::is_64(file);
  }

  static bool check_layout(const MachO_Binary& bin, std::string* error) {
    return LIEF::MachO::check_layout(
        static_cast<const LIEF::MachO::Binary&>(bin.get()), error
    );
  }

  static bool check_layout_fat(const MachO_FatBinary& bin, std::string* error) {
    return LIEF::MachO::check_layout(
        static_cast<const LIEF::MachO::FatBinary&>(bin.get()), error
    );
  }
};
