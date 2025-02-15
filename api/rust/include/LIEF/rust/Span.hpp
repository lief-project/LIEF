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
#include "LIEF/span.hpp"
#include <vector>

class Span {
  public:
  uint8_t* ptr = nullptr;
  uint64_t size = 0;
};

inline Span make_span(LIEF::span<uint8_t> content) {
  return Span{content.data(), content.size()};
}

inline Span make_span(LIEF::span<const uint8_t> content) {
  return Span{const_cast<uint8_t*>(content.data()), content.size()};
}

inline Span make_span(const std::vector<uint8_t>& content) {
  return Span{const_cast<uint8_t*>(content.data()), content.size()};
}

template<size_t N>
inline Span make_span(const std::array<uint8_t, N>& array) {
  return Span{const_cast<uint8_t*>(array.data()), N};
}
