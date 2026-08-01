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
#ifndef LIEF_LOGGING_H
#define LIEF_LOGGING_H

#include "LIEF/visibility.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace spdlog {
class logger;
}


namespace LIEF::logging {

/// **Hierarchical** logging level
///
/// From a given level set, all levels below this level are enabled
///
/// For example, if Level::Info is enabled then Level::Warn, Level::Err are also
/// enabled
enum class Level : uint32_t {
  Off = 0,

  Trace,
  Debug,
  Info,
  Warn,
  Err,
  Critical,
};

/// Current log level
LIEF_API Level get_level();

LIEF_API const char* to_string(Level e);

/// Globally disable the logging module
LIEF_API void disable();

/// Globally enable the logging module
LIEF_API void enable();

/// Change the logging level (**hierarchical**)
LIEF_API void set_level(Level level);

/// Change the logger to a file-based logging and set its path
LIEF_API void set_path(const std::string& path);

/// Log a message with the LIEF's logger
LIEF_API void log(Level level, const std::string& msg);

LIEF_API void log(Level level, const std::string& fmt,
                  const std::vector<std::string>& args);

template<typename... Args>
void log(Level level, const std::string& fmt, const Args&... args) {
  std::vector<std::string> vec_args;
  vec_args.insert(vec_args.end(),
                  {static_cast<decltype(vec_args)::value_type>(args)...});
  return log(level, fmt, vec_args);
}

LIEF_API void set_logger(std::shared_ptr<spdlog::logger> logger);

LIEF_API void reset();

inline void enable_debug() {
  set_level(Level::Debug);
}

inline void debug(const std::string& msg) {
  log(Level::Debug, msg);
}

inline void debug(const std::string& fmt, const std::vector<std::string>& args) {
  log(Level::Debug, fmt, args);
}

template<typename... Args>
void debug(const std::string& fmt, const Args&... args) {
  std::vector<std::string> vec_args;
  vec_args.insert(vec_args.end(),
                  {static_cast<decltype(vec_args)::value_type>(args)...});
  return debug(fmt, vec_args);
}

// -----------------------------------------------------------------------------

inline void info(const std::string& msg) {
  log(Level::Info, msg);
}

inline void info(const std::string& fmt, const std::vector<std::string>& args) {
  log(Level::Info, fmt, args);
}

template<typename... Args>
void info(const std::string& fmt, const Args&... args) {
  std::vector<std::string> vec_args;
  vec_args.insert(vec_args.end(),
                  {static_cast<decltype(vec_args)::value_type>(args)...});
  return info(fmt, vec_args);
}

// -----------------------------------------------------------------------------

inline void warn(const std::string& msg) {
  log(Level::Warn, msg);
}

inline void warn(const std::string& fmt, const std::vector<std::string>& args) {
  log(Level::Warn, fmt, args);
}

template<typename... Args>
void warn(const std::string& fmt, const Args&... args) {
  std::vector<std::string> vec_args;
  vec_args.insert(vec_args.end(),
                  {static_cast<decltype(vec_args)::value_type>(args)...});
  return warn(fmt, vec_args);
}

// -----------------------------------------------------------------------------

inline void err(const std::string& msg) {
  log(Level::Err, msg);
}

inline void err(const std::string& fmt, const std::vector<std::string>& args) {
  log(Level::Err, fmt, args);
}

template<typename... Args>
void err(const std::string& fmt, const Args&... args) {
  std::vector<std::string> vec_args;
  vec_args.insert(vec_args.end(),
                  {static_cast<decltype(vec_args)::value_type>(args)...});
  return err(fmt, vec_args);
}

// -----------------------------------------------------------------------------

inline void critical(const std::string& msg) {
  log(Level::Critical, msg);
}

inline void critical(const std::string& fmt,
                     const std::vector<std::string>& args) {
  log(Level::Critical, fmt, args);
}

template<typename... Args>
void critical(const std::string& fmt, const Args&... args) {
  std::vector<std::string> vec_args;
  vec_args.insert(vec_args.end(),
                  {static_cast<decltype(vec_args)::value_type>(args)...});
  return critical(fmt, vec_args);
}

// -----------------------------------------------------------------------------
namespace named {
/// Get the logging level for the logger with the given name
LIEF_API Level get_level(const char* name);

/// Disable the logger with the given name
LIEF_API void disable(const char* name);

/// Enable the logger with the given name
LIEF_API void enable(const char* name);

/// Set the log level for the logger with the given name
LIEF_API void set_level(const char* name, Level level);

/// Change the logger with the given name to a file-based logging and set its path
LIEF_API void set_path(const char* name, const std::string& path);

/// Log a message with the logger whose name is provided in the first parameter
LIEF_API void log(const char* name, Level level, const std::string& msg);

/// Set a spdlog sink for the logger with the given name
LIEF_API void set_logger(const char* name, std::shared_ptr<spdlog::logger> logger);

LIEF_API spdlog::logger& get_sink(const char* name);

/// Reset the logger with the given name
LIEF_API void reset(const char* name);

/// Enable debug logging for the logger with the given name
inline void enable_debug(const char* name) {
  set_level(name, Level::Debug);
}

inline void debug(const char* name, const std::string& msg) {
  log(name, Level::Debug, msg);
}

inline void info(const char* name, const std::string& msg) {
  log(name, Level::Info, msg);
}

inline void warn(const char* name, const std::string& msg) {
  log(name, Level::Warn, msg);
}

inline void err(const char* name, const std::string& msg) {
  log(name, Level::Err, msg);
}

inline void critical(const char* name, const std::string& msg) {
  log(name, Level::Critical, msg);
}
}


class Scoped {
  public:
  Scoped(const Scoped&) = delete;
  Scoped& operator=(const Scoped&) = delete;

  Scoped(Scoped&&) = delete;
  Scoped& operator=(Scoped&&) = delete;

  explicit Scoped(Level level) :
    level_(get_level()) {
    set_level(level);
  }

  explicit Scoped(Level level, std::string name) :
    level_(get_level()),
    name_(std::move(name)) {
    set_level(level);
  }

  const Scoped& set_level(Level lvl) const {
    if (name_.empty()) {
      logging::set_level(lvl);
    } else {
      logging::named::set_level(name_.c_str(), lvl);
    }
    return *this;
  }

  void reset() {
    set_level(level_);
  }

  ~Scoped() {
    reset();
  }

  private:
  Level level_ = Level::Info;
  std::string name_;
};


}


#endif
