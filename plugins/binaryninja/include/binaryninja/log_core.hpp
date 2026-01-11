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
#include <binaryninja/log.hpp>

#define BN_PLUGIN_LOG_NAME "lief-binaryninja"

#define BN_TRACE(...) binaryninja::core::Logger::instance(BN_PLUGIN_LOG_NAME).trace(__VA_ARGS__)
#define BN_DEBUG(...) binaryninja::core::Logger::instance(BN_PLUGIN_LOG_NAME).debug(__VA_ARGS__)
#define BN_INFO(...)  binaryninja::core::Logger::instance(BN_PLUGIN_LOG_NAME).info(__VA_ARGS__)
#define BN_WARN(...)  binaryninja::core::Logger::instance(BN_PLUGIN_LOG_NAME).warn(__VA_ARGS__)
#define BN_ERR(...)   binaryninja::core::Logger::instance(BN_PLUGIN_LOG_NAME).err(__VA_ARGS__)

namespace binaryninja::core {
inline void enable_debug_log() {
  Logger::instance(BN_PLUGIN_LOG_NAME).set_level(Logger::LEVEL::DEBUG);
}
}
