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
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/helpers.hpp"

class MachO_Dylib : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::DylibCommand;
  MachO_Dylib(const lief_t& base) :
    MachO_Command(base) {}

  auto name() const {
    return to_unique_string(impl().name());
  }
  uint32_t timestamp() const {
    return impl().timestamp();
  }

  auto name_offset() const {
    return impl().name_offset();
  }

  auto current_version() const {
    return make_unique_vector<uint64_t>(
        details::make_vector(impl().current_version())
    );
  }

  auto compatibility_version() const {
    return make_unique_vector<uint64_t>(
        details::make_vector(impl().compatibility_version())
    );
  }

  auto set_name(const std::string& name) {
    impl().name(name);
  }

  static auto id_dylib(const std::string& name, uint32_t timestamp,
                       uint32_t current_version, uint32_t compat_version) {
    return std::make_unique<MachO_Dylib>(
        lief_t::id_dylib(name, timestamp, current_version, compat_version)
    );
  }

  static auto load_dylib(const std::string& name, uint32_t timestamp,
                         uint32_t current_version, uint32_t compat_version) {
    return std::make_unique<MachO_Dylib>(
        lief_t::load_dylib(name, timestamp, current_version, compat_version)
    );
  }

  static auto reexport_dylib(const std::string& name, uint32_t timestamp,
                             uint32_t current_version, uint32_t compat_version) {
    return std::make_unique<MachO_Dylib>(
        lief_t::reexport_dylib(name, timestamp, current_version, compat_version)
    );
  }

  static auto weak_dylib(const std::string& name, uint32_t timestamp,
                         uint32_t current_version, uint32_t compat_version) {
    return std::make_unique<MachO_Dylib>(
        lief_t::weak_dylib(name, timestamp, current_version, compat_version)
    );
  }

  static auto lazy_load_dylib(const std::string& name, uint32_t timestamp,
                              uint32_t current_version, uint32_t compat_version) {
    return std::make_unique<MachO_Dylib>(
        lief_t::lazy_load_dylib(name, timestamp, current_version, compat_version)
    );
  }

  static auto classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
  lief_t& impl() {
    return as<lief_t>(this);
  }
};
