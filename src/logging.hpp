/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_PRIVATE_LOGGING_H_
#define LIEF_PRIVATE_LOGGING_H_
#include <memory>
#include <chrono>
#include "LIEF/logging.hpp" // Public interface
#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/config.h"

#include <spdlog/spdlog.h>
#include <spdlog/stopwatch.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/chrono.h>

#define LIEF_TRACE(...) LIEF::logging::Logger::trace(__VA_ARGS__)
#define LIEF_DEBUG(...) LIEF::logging::Logger::debug(__VA_ARGS__)
#define LIEF_INFO(...)  LIEF::logging::Logger::info(__VA_ARGS__)
#define LIEF_WARN(...)  LIEF::logging::Logger::warn(__VA_ARGS__)
#define LIEF_ERR(...)   LIEF::logging::Logger::err(__VA_ARGS__)

#define LIEF_SW_START(X) spdlog::stopwatch X;
#define LIEF_SW_END(...) LIEF_INFO(__VA_ARGS__);

#define CHECK(X, ...)        \
  do {                       \
    if (!(X)) {              \
      LIEF_ERR(__VA_ARGS__); \
    }                        \
  } while (false)


using std::chrono::duration_cast;
using std::chrono::milliseconds;

namespace LIEF {
namespace logging {

// TODO(romain): Update when moving to C++17
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
  static void set_level(LOGGING_LEVEL level);

  template <typename... Args>
  static void trace(const char *fmt, const Args &... args) {
    if /* constexpr */ (lief_logging_support && lief_logging_debug) {
      Logger::instance().sink_->trace(fmt, args...);
    }
  }

  template <typename... Args>
  static void debug(const char *fmt, const Args &... args) {
    if /* constexpr */ (lief_logging_support && lief_logging_debug) {
      Logger::instance().sink_->debug(fmt, args...);
    }
  }

  template <typename... Args>
  static void info(const char *fmt, const Args &... args) {
    if /* constexpr */ (lief_logging_support) {
      Logger::instance().sink_->info(fmt, args...);
    }
  }

  template <typename... Args>
  static void err(const char *fmt, const Args &... args) {
    if /* constexpr */ (lief_logging_support) {
      Logger::instance().sink_->error(fmt, args...);
    }
  }

  template <typename... Args>
  static void warn(const char *fmt, const Args &... args) {
    if /* constexpr */ (lief_logging_support) {
      Logger::instance().sink_->warn(fmt, args...);
    }
  }

  ~Logger();
  private:
  Logger();
  Logger(Logger&&);
  Logger& operator=(Logger&&);

  static void destroy();
  /* inline */ static Logger* instance_;
  std::shared_ptr<spdlog::logger> sink_;
};

}
}

#endif
