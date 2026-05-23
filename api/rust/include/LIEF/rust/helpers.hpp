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
#include <type_traits>
#include <array>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>

template<class T>
using unique_vector = std::unique_ptr<std::vector<T>>;

template<typename T>
inline auto to_int(T value) {
  using underlying_t = typename std::underlying_type_t<T>;
  static_assert(std::is_enum_v<T>, "Must be an enum");
  return static_cast<underlying_t>(value);
}

inline auto to_unique_string(std::string s) {
  return std::make_unique<std::string>(std::move(s));
}

template<typename T>
inline auto as_u8(T value) {
  return static_cast<uint8_t>(value);
}

template<typename T>
inline auto as_u16(T value) {
  return static_cast<uint16_t>(value);
}

template<typename T>
inline auto as_u32(T value) {
  return static_cast<uint32_t>(value);
}

template<typename T>
inline auto as_u64(T value) {
  return static_cast<uint64_t>(value);
}

template<typename T>
inline auto as_i32(T value) {
  return static_cast<int32_t>(value);
}

template<typename T>
inline auto as_i64(T value) {
  return static_cast<int64_t>(value);
}

template<class T, typename... Args>
unique_vector<T> make_unique_vector(Args... args) {
  return std::make_unique<std::vector<T>>(std::forward<Args>(args)...);
}

template<class T, size_t N>
inline unique_vector<uint64_t> to_vector(const std::array<T, N>& array) {
  auto result = make_unique_vector<uint64_t>();
  result->reserve(array.size());
  std::transform(array.begin(), array.end(), std::back_inserter(*result),
                 [](const T& value) { return (uint64_t)value; });
  return result;
}

template<class T>
inline unique_vector<uint64_t> to_vector(const std::vector<T>& vec) {
  if (vec.empty()) {
    return {};
  }
  auto result = make_unique_vector<uint64_t>();
  result->reserve(vec.size());
  std::transform(vec.begin(), vec.end(), std::back_inserter(*result),
                 [](const T& value) { return (uint64_t)value; });
  return result;
}
