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
#include <cstdint>

#include "LIEF/PE/resources/ResourceIcon.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Span.hpp"

class PE_ResourceIcon : private Mirror<LIEF::PE::ResourceIcon> {
  public:
  using lief_t = LIEF::PE::ResourceIcon;
  using Mirror::Mirror;

  auto id() const {
    return get().id();
  }
  auto lang() const {
    return get().lang();
  }
  auto sublang() const {
    return get().sublang();
  }
  auto width() const {
    return get().width();
  }
  auto height() const {
    return get().height();
  }
  auto color_count() const {
    return get().color_count();
  }
  auto reserved() const {
    return get().reserved();
  }
  auto planes() const {
    return get().planes();
  }
  auto bit_count() const {
    return get().bit_count();
  }
  auto size() const {
    return get().size();
  }

  Span pixels() const {
    return make_span(get().pixels());
  }
};
