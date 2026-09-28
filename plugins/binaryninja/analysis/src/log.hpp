/* Copyright 2025 - 2026 R. Thomas
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
#include <string_view>
#include <utility>

#include <binaryninja/log.hpp>
#include <fmt/base.h>

namespace analysis_plugin {
using Logger = binaryninja::core::Logger;

inline constexpr std::string_view BN_PLUGIN_ANALYSIS_LOG_NAME =
    "lief-analysis-plugin";

template<typename... Args>
void BN_TRACE(fmt::format_string<Args...> format, Args&&... args) {
  Logger::instance(BN_PLUGIN_ANALYSIS_LOG_NAME)
      .trace(format, std::forward<Args>(args)...);
}

template<typename... Args>
void BN_DEBUG(fmt::format_string<Args...> format, Args&&... args) {
  Logger::instance(BN_PLUGIN_ANALYSIS_LOG_NAME)
      .debug(format, std::forward<Args>(args)...);
}

template<typename... Args>
void BN_INFO(fmt::format_string<Args...> format, Args&&... args) {
  Logger::instance(BN_PLUGIN_ANALYSIS_LOG_NAME)
      .info(format, std::forward<Args>(args)...);
}

template<typename... Args>
void BN_WARN(fmt::format_string<Args...> format, Args&&... args) {
  Logger::instance(BN_PLUGIN_ANALYSIS_LOG_NAME)
      .warn(format, std::forward<Args>(args)...);
}

template<typename... Args>
void BN_ERR(fmt::format_string<Args...> format, Args&&... args) {
  Logger::instance(BN_PLUGIN_ANALYSIS_LOG_NAME)
      .error(format, std::forward<Args>(args)...);
}

inline void enable_debug_log() {
  Logger::instance(BN_PLUGIN_ANALYSIS_LOG_NAME).set_level(Logger::Level::Debug);
}
}
