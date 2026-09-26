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
#ifndef LIEF_PRIVATE_LOGGING_H
#define LIEF_PRIVATE_LOGGING_H
#include <memory>
#include <sstream>
#include <utility>

#include "LIEF/config.h"
#include "LIEF/logging.hpp" // Public interface

#include "messages.hpp"

#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ranges.h>
#include <spdlog/spdlog.h>

#define CHECK(X, ...)                                                             \
  do {                                                                            \
    if (!(X)) {                                                                   \
      LIEF_ERR(__VA_ARGS__);                                                      \
    }                                                                             \
  } while (false)


#define CHECK_FATAL(X, ...)                                                       \
  do {                                                                            \
    if ((X)) {                                                                    \
      LIEF_ERR(__VA_ARGS__);                                                      \
      std::abort();                                                               \
    }                                                                             \
  } while (false)

#if defined(LIEF_LOGGING_DEBUG)
  #define LIEF_LOG_LOCATION()                                                     \
    do {                                                                          \
      LIEF_DEBUG("{}:{}", __FUNCTION__, __LINE__);                                \
    } while (false)
#else
  #define LIEF_LOG_LOCATION()
#endif


namespace LIEF::logging {

class Logger {
  public:
  static constexpr auto DEFAULT_NAME = "LIEF";
  using instances_t = std::unordered_map<std::string, std::unique_ptr<Logger>>;
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  static Logger& instance(const char* name);
  static Logger& instance() {
    return Logger::instance(DEFAULT_NAME);
  }

  void disable() {
    if constexpr (lief_logging_support) {
      sink_->set_level(spdlog::level::off);
    }
  }

  void enable() {
    if constexpr (lief_logging_support) {
      sink_->set_level(spdlog::level::warn);
    }
  }

  void set_level(Level level);

  Level get_level();

  Logger& set_log_path(const std::string& path);

  void reset();

  template<typename... Args>
  void trace(fmt::format_string<Args...> fmt, Args&&... args) {
    if constexpr (lief_logging_support && lief_logging_debug) {
      sink_->trace(fmt, std::forward<Args>(args)...);
    }
  }

  template<typename... Args>
  void debug(fmt::format_string<Args...> fmt, Args&&... args) {
    if constexpr (lief_logging_support && lief_logging_debug) {
      sink_->debug(fmt, std::forward<Args>(args)...);
    }
  }

  template<typename... Args>
  void info(fmt::format_string<Args...> fmt, Args&&... args) {
    if constexpr (lief_logging_support) {
      sink_->info(fmt, std::forward<Args>(args)...);
    }
  }

  template<typename... Args>
  void err(fmt::format_string<Args...> fmt, Args&&... args) {
    if constexpr (lief_logging_support) {
      sink_->error(fmt, std::forward<Args>(args)...);
    }
  }

  template<typename... Args>
  void warn(fmt::format_string<Args...> fmt, Args&&... args) {
    if constexpr (lief_logging_support) {
      sink_->warn(fmt, std::forward<Args>(args)...);
    }
  }

  template<typename... Args>
  void critial(fmt::format_string<Args...> fmt, Args&&... args) {
    if constexpr (lief_logging_support) {
      sink_->critical(fmt, std::forward<Args>(args)...);
    }
  }

  void set_logger(std::shared_ptr<spdlog::logger> logger);

  spdlog::logger& sink() {
    assert(sink_ != nullptr);
    return *sink_;
  }

  ~Logger() = default;
  Logger() = delete;

  private:
  Logger(std::shared_ptr<spdlog::logger> sink) :
    sink_(std::move(sink)) {}
  Logger(Logger&&) noexcept = default;
  Logger& operator=(Logger&&) noexcept = default;

  std::shared_ptr<spdlog::logger> sink_;
};

}

template<typename... Args>
void LIEF_TRACE(fmt::format_string<Args...> fmt, Args&&... args) {
  LIEF::logging::Logger::instance().trace(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void LIEF_DEBUG(fmt::format_string<Args...> fmt, Args&&... args) {
  LIEF::logging::Logger::instance().debug(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void LIEF_INFO(fmt::format_string<Args...> fmt, Args&&... args) {
  LIEF::logging::Logger::instance().info(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void LIEF_WARN(fmt::format_string<Args...> fmt, Args&&... args) {
  LIEF::logging::Logger::instance().warn(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void LIEF_ERR(fmt::format_string<Args...> fmt, Args&&... args) {
  LIEF::logging::Logger::instance().err(fmt, std::forward<Args>(args)...);
}

namespace LIEF::logging {


inline void critial(const char* msg) {
  LIEF::logging::log(LIEF::logging::Level::Critical, msg);
}

template<typename... Args>
void critial(const char* fmt, const Args&... args) {
  LIEF::logging::log(LIEF::logging::Level::Critical,
                     fmt::format(fmt::runtime(fmt), args...));
}

[[noreturn]] inline void terminate() {
  std::abort();
}

[[noreturn]] inline void fatal_error(const char* msg) {
  critial(msg);
  terminate();
}

template<typename... Args>
[[noreturn]] void fatal_error(const char* fmt, const Args&... args) {
  critial(fmt, args...);
  terminate();
}

inline void needs_lief_extended() {
  if constexpr (!lief_extended) {
    Logger::instance().warn(NEEDS_EXTENDED_MSG);
  }
}

class Stream : public std::stringbuf {
  public:
  Stream(Level lvl) :
    lvl_(lvl) {}

  protected:
  int sync() override {
    switch (lvl_) {
      case Level::Off: break;

      case Level::Trace:
      case Level::Debug:
      {
        LIEF_DEBUG("{}", str());
        break;
      }

      case Level::Info:
      {
        LIEF_INFO("{}", str());
        break;
      }

      case Level::Warn:
      {
        LIEF_WARN("{}", str());
        break;
      }
      case Level::Err:
      {
        LIEF_ERR("{}", str());
        break;
      }

      case Level::Critical:
      {
        critical("{}", str());
        break;
      }
    }
    str("");
    return 0;
  }

  protected:
  Level lvl_ = Level::Off;
};

}


#endif
