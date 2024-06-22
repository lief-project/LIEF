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
#ifndef LIEF_PRIVATE_LOGGING_H
#define LIEF_PRIVATE_LOGGING_H
#include <memory>
#include "LIEF/logging.hpp" // Public interface
#include "LIEF/types.hpp"
#include "LIEF/config.h"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

#define LIEF_TRACE(...) LIEF::logging::Logger::trace(__VA_ARGS__)
#define LIEF_DEBUG(...) LIEF::logging::Logger::debug(__VA_ARGS__)
#define LIEF_INFO(...)  LIEF::logging::Logger::info(__VA_ARGS__)
#define LIEF_WARN(...)  LIEF::logging::Logger::warn(__VA_ARGS__)
#define LIEF_ERR(...)   LIEF::logging::Logger::err(__VA_ARGS__)

#define CHECK(X, ...)        \
  do {                       \
    if (!(X)) {              \
      LIEF_ERR(__VA_ARGS__); \
    }                        \
  } while (false)


#define CHECK_FATAL(X, ...)  \
  do {                       \
    if ((X)) {               \
      LIEF_ERR(__VA_ARGS__); \
      std::abort();          \
    }                        \
  } while (false)

namespace LIEF {
namespace logging {

class Logger {
  public:
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  static Logger& instance();

  //! @brief Disable the logging module
  static void disable();

  //! @brief Enable the logging module
  static void enable();

  //! @brief Change the logging level (**hierarchical**)
  static void set_level(LEVEL level);

  static Logger& set_log_path(const std::string& path);

  static void reset();

  template <typename... Args>
  static void trace(const char *fmt, const Args &... args) {
    if constexpr (lief_logging_support && lief_logging_debug) {
      Logger::instance().sink_->trace(fmt, args...);
    }
  }

  template <typename... Args>
  static void debug(const char *fmt, const Args &... args) {
    if constexpr (lief_logging_support && lief_logging_debug) {
      Logger::instance().sink_->debug(fmt, args...);
    }
  }

  template <typename... Args>
  static void info(const char *fmt, const Args &... args) {
    if constexpr (lief_logging_support) {
      Logger::instance().sink_->info(fmt, args...);
    }
  }

  template <typename... Args>
  static void err(const char *fmt, const Args &... args) {
    if constexpr (lief_logging_support) {
      Logger::instance().sink_->error(fmt, args...);
    }
  }

  template <typename... Args>
  static void warn(const char *fmt, const Args &... args) {
    if constexpr (lief_logging_support) {
      Logger::instance().sink_->warn(fmt, args...);
    }
  }

  static void set_logger(const spdlog::logger& logger);

  ~Logger();
  private:
  Logger();
  Logger(const std::string& filepath);
  Logger(Logger&&);
  Logger& operator=(Logger&&);

  static void destroy();
  static inline Logger* instance_ = nullptr;
  std::shared_ptr<spdlog::logger> sink_;
};

}
}

#endif
