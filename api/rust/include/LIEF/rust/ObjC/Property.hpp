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
#include "LIEF/ObjC/Property.hpp"
#include "LIEF/rust/Mirror.hpp"

class ObjC_Property : private Mirror<LIEF::objc::Property> {
  public:
  using lief_t = LIEF::objc::Property;
  using Mirror::Mirror;

  auto name() const { return get().name(); }
  auto attribute() const { return get().attribute(); }
};
