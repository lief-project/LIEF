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
#include "LIEF/logging.hpp"
#include <spdlog/fmt/fmt.h>

#if !defined(GHIDRA_LIEF_LOGGER_NAME)
#define GHIDRA_LIEF_LOGGER_NAME "ghidra-lief"
#endif

#define GHIDRA_TRACE(...) LIEF::logging::named::debug(GHIDRA_LIEF_LOGGER_NAME, ::LIEF::ghidra::fmt_str(__VA_ARGS__))
#define GHIDRA_DEBUG(...) LIEF::logging::named::debug(GHIDRA_LIEF_LOGGER_NAME, ::LIEF::ghidra::fmt_str(__VA_ARGS__))
#define GHIDRA_INFO(...)  LIEF::logging::named::info(GHIDRA_LIEF_LOGGER_NAME, ::LIEF::ghidra::fmt_str(__VA_ARGS__))
#define GHIDRA_WARN(...)  LIEF::logging::named::warn(GHIDRA_LIEF_LOGGER_NAME, ::LIEF::ghidra::fmt_str(__VA_ARGS__))
#define GHIDRA_ERR(...)   LIEF::logging::named::err(GHIDRA_LIEF_LOGGER_NAME, ::LIEF::ghidra::fmt_str(__VA_ARGS__))

namespace LIEF::ghidra {

template <typename... Args>
inline std::string fmt_str(const char *fmt, const Args &... args) {
  return fmt::format(fmt::runtime(fmt), args...);
}

[[noreturn]] inline void terminate() {
  std::abort();
}

[[noreturn]] inline void fatal_error(const char* msg) {
  LIEF::logging::named::critical(GHIDRA_LIEF_LOGGER_NAME, std::string(msg));
  terminate();
}

template <typename... Args>
[[noreturn]] void fatal_error(const char *fmt, const Args &... args) {
  LIEF::logging::named::critical(GHIDRA_LIEF_LOGGER_NAME, LIEF::ghidra::fmt_str(fmt::runtime(fmt), args...));
  terminate();
}

}
