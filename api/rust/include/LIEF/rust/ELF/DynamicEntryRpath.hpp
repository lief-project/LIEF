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
#include "LIEF/rust/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"

class ELF_DynamicEntryRpath : public ELF_DynamicEntry {
  public:
  using lief_t = LIEF::ELF::DynamicEntryRpath;

  ELF_DynamicEntryRpath(std::unique_ptr<lief_t> impl) :
    ELF_DynamicEntry(std::move(impl)) {}

  static auto create(const std::string& name) {
    return std::make_unique<ELF_DynamicEntryRpath>(std::make_unique<lief_t>(name));
  }

  auto rpath() const {
    return to_unique_string(impl().rpath());
  }
  auto paths() const {
    return make_unique_vector<std::string>(impl().paths());
  }

  auto insert(uint32_t pos, const std::string& name) {
    impl().insert(pos, name);
  }

  auto append(const std::string& name) {
    impl().append(name);
  }

  auto remove(const std::string& path) {
    impl().remove(path);
  }

  auto set_rpath(const std::string& path) {
    impl().rpath(path);
  }

  static auto classof(const ELF_DynamicEntry& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
  lief_t& impl() {
    return as<lief_t>(this);
  }
};
