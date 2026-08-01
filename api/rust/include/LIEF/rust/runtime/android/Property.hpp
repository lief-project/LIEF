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

#include <vector>

#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

#include "LIEF/runtime/android/Property.hpp"

class runtime_android_Property : public Mirror<LIEF::runtime::android::Property> {
  public:
  using lief_t = LIEF::runtime::android::Property;
  using Mirror::Mirror;

  auto name() const {
    return to_unique_string(get().name());
  }

  auto value() const {
    return to_unique_string(get().value());
  }

  auto serial() const {
    return get().serial();
  }

  auto to_string() const {
    return to_unique_string(get().to_string());
  }
};

class runtime_android_it_properties
  : public ContainerIterator<runtime_android_Property,
                             std::vector<LIEF::runtime::android::Property>> {
  public:
  runtime_android_it_properties(
      std::vector<LIEF::runtime::android::Property> properties
  ) :
    ContainerIterator(std::move(properties)) {}

  // NOLINTNEXTLINE
  auto next() {
    return ContainerIterator::next();
  }
};
