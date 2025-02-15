/* Copyright 2022 - 2025 R. Thomas
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
#include "LIEF/utils.hpp"
#include "LIEF/rust/error.hpp"

inline bool is_extended() {
  return LIEF::is_extended();
}

inline std::string demangle(std::string mangled, uint32_t& err) {
  return details::make_error<std::string>(LIEF::demangle(mangled), err);
}

inline std::string extended_version_info() {
  return LIEF::extended_version_info();
}

inline std::string dump(const uint8_t* buffer, size_t size) {
  return LIEF::dump(buffer, size);
}

inline std::string dump_with_limit(const uint8_t* buffer, size_t size,
                                   uint64_t limit) {
  return LIEF::dump(buffer, size, /*title=*/"", /*prefix=*/"", limit);
}
