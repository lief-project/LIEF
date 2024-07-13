/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/ObjC/IVar.hpp"
#include "LIEF/rust/Mirror.hpp"

class ObjC_IVar : private Mirror<LIEF::objc::IVar> {
  public:
  using lief_t = LIEF::objc::IVar;
  using Mirror::Mirror;

  auto name() const { return get().name(); }
  auto mangled_type() const { return get().mangled_type(); }
};
