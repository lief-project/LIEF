/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_PATH_H
#define LIEF_PATH_H
#include <type_traits>
#include <filesystem>

namespace LIEF {

/// Whether `T` is a `std::filesystem::path`
template<class T>
inline constexpr bool is_path_v =
    std::is_same_v<std::decay_t<T>, std::filesystem::path>;

/// Helper used by the functions that expose both a `std::string_view` and a
/// `std::filesystem::path` overload to avoid ambiguous resolution
/// (e.g. LIEF::ELF::Parser::parse).
template<class... Ts>
using enable_if_path_t = std::enable_if_t<(is_path_v<Ts> || ...), int>;

}

#endif
