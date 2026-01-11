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
#include "LIEF/ELF/DynamicSharedObject.hpp"

class ELF_DynamicSharedObject : public ELF_DynamicEntry {
  public:
  using lief_t = LIEF::ELF::DynamicSharedObject;
  ELF_DynamicSharedObject(std::unique_ptr<lief_t> impl) :
    ELF_DynamicEntry(std::move(impl))
  {}

  static auto create(std::string name) {
    return std::make_unique<ELF_DynamicSharedObject>(
        std::make_unique<lief_t>(std::move(name)));
  }

  std::string name() const { return impl().name(); }

  void set_name(std::string name) { impl().name(std::move(name)); }

  static bool classof(const ELF_DynamicEntry& entry) {
    return lief_t::classof(&entry.get());
  }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
  lief_t& impl() { return as<lief_t>(this); }
};
