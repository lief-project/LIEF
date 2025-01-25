
/* Copyright 2024 - 2025 R. Thomas
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
#include <LIEF/Abstract/Function.hpp>
#include <LIEF/rust/Abstract/Symbol.hpp>
#include <LIEF/rust/Mirror.hpp>
#include <LIEF/rust/helpers.hpp>

class AbstractFunction : public AbstractSymbol {
  public:
  using lief_t = LIEF::Function;
  AbstractFunction(const lief_t& obj) : AbstractSymbol(obj) {}

  auto address() const { return impl().address(); }
  auto flags() const { return to_int(impl().flags()); }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
