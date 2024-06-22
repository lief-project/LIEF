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

Logger::Logger(Logger&&) = default;
Logger& Logger::operator=(Logger&&) = default;
Logger::~Logger() = default;

Logger::Logger() {
  if constexpr (lief_logging_support) {
    if constexpr (current_platform() == PLATFORMS::ANDROID_PLAT) {
      #if defined(__ANDROID__)
      sink_ = spdlog::android_logger_mt("LIEF", "lief");
      #else
      // Should not append ...
      #endif
    }
    else if (current_platform() == PLATFORMS::IOS) {
      sink_ = spdlog::basic_logger_mt("LIEF", "/tmp/lief.log", /* truncate */ true);
    }
    else {
      sink_ = spdlog::stderr_color_mt("LIEF");
    }


    sink_->set_level(spdlog::level::warn);
    sink_->set_pattern("%v");
    sink_->flush_on(spdlog::level::warn);
  }
}


Logger::Logger(const std::string& filepath) {
  sink_ = spdlog::basic_logger_mt("LIEF", filepath, /* truncate */ true);
  sink_->set_level(spdlog::level::warn);
  sink_->set_pattern("%v");
  sink_->flush_on(spdlog::level::warn);

}

Logger& Logger::instance() {
  if (instance_ == nullptr) {
    instance_ = new Logger{};
    std::atexit(destroy);
  }
  return *instance_;
}

void Logger::reset() {
  Logger::destroy();
  Logger::instance();
}

void Logger::destroy() {
  spdlog::details::registry::instance().drop("LIEF");
  delete instance_;
  instance_ = nullptr;
}

Logger& Logger::set_log_path(const std::string& path) {
  if (instance_ == nullptr) {
    instance_ = new Logger{path};
    std::atexit(destroy);
    return *instance_;
  }
  auto& logger = Logger::instance();
  spdlog::details::registry::instance().drop("LIEF");
  logger.sink_ = spdlog::basic_logger_mt("LIEF", path,
                                         /*truncate=*/true);
  logger.sink_->set_pattern("%v");
  logger.sink_->set_level(spdlog::level::warn);
  logger.sink_->flush_on(spdlog::level::warn);
  return logger;
}

void Logger::set_logger(const spdlog::logger& logger) {
  if (logger.name() != "LIEF") {
    return;
  }

  auto& instance = Logger::instance();
  spdlog::details::registry::instance().drop("LIEF");

  instance.sink_ = std::make_shared<spdlog::logger>(logger);
  instance.sink_->set_pattern("%v");
  instance.sink_->set_level(spdlog::level::warn);
  instance.sink_->flush_on(spdlog::level::warn);
}

const char* to_string(LEVEL e) {
  switch (e) {
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


void Logger::disable() {
  if constexpr (lief_logging_support) {
    Logger::instance().sink_->set_level(spdlog::level::off);
  }
}

void Logger::enable() {
  if constexpr (lief_logging_support) {
    Logger::instance().sink_->set_level(spdlog::level::warn);
  }
}

void Logger::set_level(LEVEL level) {
  if constexpr (!lief_logging_support) {
    return;
  }
  switch (level) {
    case LEVEL::TRACE:
      {
        Logger::instance().sink_->set_level(spdlog::level::trace);
        Logger::instance().sink_->flush_on(spdlog::level::trace);
        break;
      }

    case LEVEL::DEBUG:
      {
        Logger::instance().sink_->set_level(spdlog::level::debug);
        Logger::instance().sink_->flush_on(spdlog::level::debug);
        break;
      }

    case LEVEL::INFO:
      {
        Logger::instance().sink_->set_level(spdlog::level::info);
        Logger::instance().sink_->flush_on(spdlog::level::info);
        break;
      }

    default:
    case LEVEL::WARN:
      {
        Logger::instance().sink_->set_level(spdlog::level::warn);
        Logger::instance().sink_->flush_on(spdlog::level::warn);
        break;
      }

    case LEVEL::ERR:
      {
        Logger::instance().sink_->set_level(spdlog::level::err);
        Logger::instance().sink_->flush_on(spdlog::level::err);
        break;
      }

    case LEVEL::CRITICAL:
      {
        Logger::instance().sink_->set_level(spdlog::level::critical);
        Logger::instance().sink_->flush_on(spdlog::level::critical);
        break;
      }
  }
}

// Public interface

void disable() {
  Logger::disable();
}

void enable() {
  Logger::enable();
}

void set_level(LEVEL level) {
  Logger::set_level(level);
}

void set_path(const std::string& path) {
  Logger::set_log_path(path);
}

void set_logger(const spdlog::logger& logger) {
  Logger::set_logger(logger);
}

void reset() {
  Logger::reset();
}

void log(LEVEL level, const std::string& msg) {
  switch (level) {
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


