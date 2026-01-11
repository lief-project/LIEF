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
#include <LIEF/Abstract/Symbol.hpp>
#include <LIEF/rust/Mirror.hpp>

#include <string>

class AbstractSymbol : public Mirror<LIEF::Symbol> {
  public:
  using Mirror::Mirror;

  std::string name() const { return get().name(); }
  auto size() const { return get().size(); }
  auto value() const { return get().value(); }

  void set_name(std::string name) {
    get().name(std::move(name));
  }

  void set_value(uint64_t value) {
    get().value(value);
  }

  void set_size(uint64_t sz) {
    get().size(sz);
  }
};
