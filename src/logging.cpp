/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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

#include "LIEF/config.h"
#include "LIEF/logging.hpp"
#include "LIEF/platforms.hpp"
#include "logging.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/fmt/bundled/args.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/android_sink.h"

namespace LIEF {
namespace logging {

std::shared_ptr<spdlog::logger> default_logger(
  [[maybe_unused]] const std::string& name = "LIEF",
  [[maybe_unused]] const std::string& logcat_tag = "lief",
  [[maybe_unused]] const std::string& filepath = "/tmp/lief.log",
  bool truncate = true
)
{
  auto& registry = spdlog::details::registry::instance();
  if (std::shared_ptr<spdlog::logger> _ = registry.get(name)) {
    registry.drop(name);
  }

  std::shared_ptr<spdlog::logger> sink;
  if constexpr (current_platform() == PLATFORMS::ANDROID_PLAT) {
#if defined(__ANDROID__)
    sink = spdlog::android_logger_mt(name, logcat_tag);
#endif
  }
  else if (current_platform() == PLATFORMS::IOS) {
    sink = spdlog::basic_logger_mt(name, filepath, truncate);
  }
  else {
    sink = spdlog::stderr_color_mt(name);
  }

  sink->set_level(spdlog::level::warn);
  sink->set_pattern("%v");
  sink->flush_on(spdlog::level::warn);
  return sink;
}

LEVEL Logger::get_level() {
  spdlog::level::level_enum lvl = sink_->level();
  switch (lvl) {
    default:
    case spdlog::level::level_enum::off:
      return LEVEL::OFF;
    case spdlog::level::level_enum::trace:
      return LEVEL::TRACE;
    case spdlog::level::level_enum::debug:
      return LEVEL::DEBUG;
    case spdlog::level::level_enum::info:
      return LEVEL::INFO;
    case spdlog::level::level_enum::warn:
      return LEVEL::WARN;
    case spdlog::level::level_enum::err:
      return LEVEL::ERR;
    case spdlog::level::level_enum::critical:
      return LEVEL::CRITICAL;
  }
  return LEVEL::TRACE;
}

Logger& Logger::instance(const char* name) {
  Logger* logger = nullptr;
  if (auto it = instances_.find(name); it == instances_.end()) {
    if (instances_.empty()) {
      std::atexit(destroy);
    }
    logger = instances_.insert({name, new Logger(default_logger())}).first->second;
  } else {
    logger = it->second;
  }
  return *logger;
}

void Logger::reset() {
  set_logger(*default_logger());
}

void Logger::destroy() {
  for (const auto& [name, instance] : instances_) {
    spdlog::details::registry::instance().drop(instance->sink_->name());
    delete instance;
  }
  instances_.clear();
}

Logger& Logger::set_log_path(const std::string& path) {
  auto& registry = spdlog::details::registry::instance();
  if (std::shared_ptr<spdlog::logger> _ = registry.get(DEFAULT_NAME)) {
    registry.drop(DEFAULT_NAME);
  }
  auto logger = spdlog::basic_logger_mt(DEFAULT_NAME, path, /*truncate=*/true);
  set_logger(*logger);
  return *this;
}

void Logger::set_logger(const spdlog::logger& logger) {
  auto& registry = spdlog::details::registry::instance();
  if (std::shared_ptr<spdlog::logger> _ = registry.get(logger.name())) {
    registry.drop(logger.name());
  }

  sink_ = std::make_shared<spdlog::logger>(logger);
  sink_->set_pattern("%v");
  sink_->set_level(spdlog::level::warn);
  sink_->flush_on(spdlog::level::warn);

  registry.register_logger(sink_);
}

const char* to_string(LEVEL e) {
  switch (e) {
    case LEVEL::OFF: return "OFF";
    case LEVEL::TRACE: return "TRACE";
    case LEVEL::DEBUG: return "DEBUG";
    case LEVEL::INFO: return "INFO";
    case LEVEL::ERR: return "ERROR";
    case LEVEL::WARN: return "WARN";
    case LEVEL::CRITICAL: return "CRITICAL";
    default: return "UNDEFINED";
  }
  return "UNDEFINED";
}

void Logger::set_level(LEVEL level) {
  if constexpr (!lief_logging_support) {
    return;
  }
  switch (level) {
    case LEVEL::OFF:
      {
        sink_->set_level(spdlog::level::off);
        sink_->flush_on(spdlog::level::off);
        break;
      }

    case LEVEL::TRACE:
      {
        sink_->set_level(spdlog::level::trace);
        sink_->flush_on(spdlog::level::trace);
        break;
      }

    case LEVEL::DEBUG:
      {
        sink_->set_level(spdlog::level::debug);
        sink_->flush_on(spdlog::level::debug);
        break;
      }

    case LEVEL::INFO:
      {
        sink_->set_level(spdlog::level::info);
        sink_->flush_on(spdlog::level::info);
        break;
      }

    default:
    case LEVEL::WARN:
      {
        sink_->set_level(spdlog::level::warn);
        sink_->flush_on(spdlog::level::warn);
        break;
      }

    case LEVEL::ERR:
      {
        sink_->set_level(spdlog::level::err);
        sink_->flush_on(spdlog::level::err);
        break;
      }

    case LEVEL::CRITICAL:
      {
        sink_->set_level(spdlog::level::critical);
        sink_->flush_on(spdlog::level::critical);
        break;
      }
  }
}

// Public interface

void disable() {
  Logger::instance().disable();
}

void enable() {
  Logger::instance().enable();
}

void set_level(LEVEL level) {
  Logger::instance().set_level(level);
}

void set_path(const std::string& path) {
  Logger::instance().set_log_path(path);
}

void set_logger(const spdlog::logger& logger) {
  Logger::instance().set_logger(logger);
}

void reset() {
  Logger::instance().reset();
}

LEVEL get_level() {
  return Logger::instance().get_level();
}

void log(LEVEL level, const std::string& msg) {
  switch (level) {
    case LEVEL::OFF:
      break;
    case LEVEL::TRACE:
    case LEVEL::DEBUG:
      {
        LIEF_DEBUG("{}", msg);
        break;
      }
    case LEVEL::INFO:
      {
        LIEF_INFO("{}", msg);
        break;
      }
    case LEVEL::WARN:
      {
        LIEF_WARN("{}", msg);
        break;
      }
    case LEVEL::CRITICAL:
    case LEVEL::ERR:
      {
        LIEF_ERR("{}", msg);
        break;
      }
  }
}

void log(LEVEL level, const std::string& fmt,
         const std::vector<std::string>& args)
{
  fmt::dynamic_format_arg_store<fmt::format_context> store;
  for (const std::string& arg : args) {
    store.push_back(arg);
  }
  std::string result = fmt::vformat(fmt, store);
  log(level, result);
}


}
}


