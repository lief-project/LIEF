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
#include "LIEF/rust/PE/Binary.hpp"
#include "LIEF/rust/PE/Import.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

class PE_Utils {
  public:
  static bool is_pe(std::string file) { // NOLINT(performance-unnecessary-value-param)
    return LIEF::PE::is_pe(file);
  }

  static bool check_layout(const PE_Binary& bin, std::string* error) {
    return LIEF::PE::check_layout(static_cast<const LIEF::PE::Binary&>(bin.get()), error);
  }

  static uint32_t get_type(std::string file) { // NOLINT(performance-unnecessary-value-param)
    if (auto res = LIEF::PE::get_type(file)) {
      return static_cast<uint32_t>(*res);
    }
    return 0;
  }

  static std::string get_imphash(const PE_Binary& bin, uint32_t mode) {
    return LIEF::PE::get_imphash(
      static_cast<const LIEF::PE::Binary&>(bin.get()),
      LIEF::PE::IMPHASH_MODE(mode));
  }

  static std::string oid_to_string(std::string oid) { // NOLINT(performance-unnecessary-value-param)
    const char* result = LIEF::PE::oid_to_string(oid);
    return result ? std::string(result) : "";
  }

  static std::unique_ptr<PE_Import> resolve_ordinals(
      const PE_Import& imp, bool strict, bool use_std)
  {
    if (auto res = LIEF::PE::resolve_ordinals(imp.get(), strict, use_std)) {
      return std::make_unique<PE_Import>(
          std::make_unique<LIEF::PE::Import>(std::move(*res)));
    }
    return nullptr;
  }
};
