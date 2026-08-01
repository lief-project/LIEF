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

#include "LIEF/runtime/Module.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class runtime_Module : public Mirror<LIEF::runtime::Module> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::runtime::Module;

  auto name() const {
    return to_unique_string(get().name());
  }
  auto path() const {
    return to_unique_string(get().path());
  }
  auto imagebase() const {
    return get().imagebase();
  }

  uint64_t size() const {
    return get().size();
  }
  auto end() const {
    return get().end();
  }

  auto contains(uint64_t addr) const {
    return get().contains(addr);
  }
};


class runtime_it_modules
  : public ForwardIterator<runtime_Module, LIEF::runtime::Module::Iterator> {
  public:
  runtime_it_modules() :
    ForwardIterator(LIEF::runtime::modules()) {}

  auto next() {
    return ForwardIterator::next();
  }
};

inline auto runtime_modules() {
  return std::make_unique<runtime_it_modules>();
}

inline auto runtime_module_from_name(const std::string& name) {
  return details::try_unique<runtime_Module>(
      LIEF::runtime::module_from_name(name)
  );
}

inline auto runtime_module_from_path(const std::string& path) {
  return details::try_unique<runtime_Module>(
      LIEF::runtime::module_from_path(path)
  );
}

inline auto runtime_module_from_addr(uint64_t addr) {
  return details::try_unique<runtime_Module>(
      LIEF::runtime::module_from_addr(addr)
  );
}
