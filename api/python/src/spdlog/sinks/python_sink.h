#pragma once

#include <spdlog/sinks/base_sink.h>
#include <spdlog/details/synchronous_factory.h>
#include <spdlog/details/null_mutex.h>
#include <mutex>

#include <Python.h>

namespace spdlog {
namespace sinks {

struct py_stderr_tag {};
struct py_stdout_tag {};

template<typename Mutex, typename ErrOrOut = py_stderr_tag>
class python_base_sink final : public base_sink<Mutex> {
  public:
  explicit python_base_sink() = default;
  protected:
  void flush_() override {}
  void sink_it_(const details::log_msg &msg) override {
    memory_buf_t formatted;
    base_sink<Mutex>::formatter_->format(msg, formatted);
    std::string msg_str(formatted.data(), formatted.size());

    if constexpr (std::is_same_v<ErrOrOut, py_stderr_tag>) {
      PySys_WriteStderr("%s", msg_str.c_str());
    } else {
      PySys_WriteStdout("%s", msg_str.c_str());
    }
  }
};

using python_stderr_sink_mt = python_base_sink<std::mutex, py_stderr_tag>;
using python_stderr_sink_st = python_base_sink<details::null_mutex, py_stderr_tag>;
} // namespace sinks

template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> stderr_python_mt()
{
  return Factory::template create<sinks::python_stderr_sink_mt>();
}

template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> stderr_python_st()
{
  return Factory::template create<sinks::python_stderr_sink_st>();
}
}
