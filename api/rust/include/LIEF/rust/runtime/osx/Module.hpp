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

#include "LIEF/runtime/osx/Module.hpp"
#include "LIEF/rust/MachO/Binary.hpp"
#include "LIEF/rust/runtime/Module.hpp"

class runtime_osx_Module : public runtime_Module {
  public:
  using lief_t = LIEF::runtime::osx::Module;
  runtime_osx_Module(std::unique_ptr<lief_t> mod) :
    runtime_Module(std::move(mod)) {}

  auto handle() const {
    return reinterpret_cast<uint64_t>(impl().handle());
  }

  auto dlsym(const std::string& name) const {
    return reinterpret_cast<uint64_t>(impl().dlsym(name));
  }

  auto parse_from_path() const {
    return details::try_unique<MachO_Binary>(impl().parse_from_path());
  }

  auto parse_from_memory() const {
    return details::try_unique<MachO_Binary>(impl().parse_from_memory());
  }

  static auto from_handle(uint64_t handle) {
    return details::try_unique<runtime_osx_Module>(
        lief_t::from_handle(reinterpret_cast<void*>(handle))
    );
  }

  static bool classof(const runtime_Module& M) {
    return lief_t::classof(&M.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};

inline auto runtime_osx_dlopen(const std::string& name) {
  return details::try_unique<runtime_osx_Module>(LIEF::runtime::osx::dlopen(name));
}
