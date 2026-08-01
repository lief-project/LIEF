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

#include "LIEF/runtime/windows/Module.hpp"
#include "LIEF/rust/PE/Binary.hpp"
#include "LIEF/rust/runtime/Module.hpp"

class runtime_windows_Module : public runtime_Module {
  public:
  using lief_t = LIEF::runtime::windows::Module;
  runtime_windows_Module(std::unique_ptr<lief_t> mod) :
    runtime_Module(std::move(mod)) {}

  auto handle() const {
    return (uint64_t)impl().handle();
  }

  auto dlsym(const std::string& name) const {
    return reinterpret_cast<uint64_t>(impl().dlsym(name));
  }

  auto parse_from_path() const {
    return details::try_unique<PE_Binary>(impl().parse_from_path());
  }

  auto parse_from_path_with_config(const PE_ParserConfig& config) const {
    return details::try_unique<PE_Binary>(impl().parse_from_path(config.conf()));
  }

  auto parse_from_memory() const {
    return details::try_unique<PE_Binary>(impl().parse_from_memory());
  }

  auto parse_from_memory_with_config(const PE_ParserConfig& config) const {
    return details::try_unique<PE_Binary>(impl().parse_from_memory(config.conf()));
  }

  static bool classof(const runtime_Module& M) {
    return lief_t::classof(&M.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

inline auto runtime_windows_dlopen(const std::string& name) {
  return details::try_unique<runtime_windows_Module>(
      LIEF::runtime::windows::dlopen(name)
  );
}

inline auto runtime_windows_find_module(const std::string& name) {
  return details::try_unique<runtime_windows_Module>(
      LIEF::runtime::windows::find_module(name)
  );
}
