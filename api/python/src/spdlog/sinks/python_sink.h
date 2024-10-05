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
    // See: https://github.com/python/cpython/blob/453da532fee26dc4f83d4cab77eb9bdb17b941e6/Python/sysmodule.c#L4001
    static constexpr auto BUFFER_SIZE = 1000;
    memory_buf_t formatted;
    base_sink<Mutex>::formatter_->format(msg, formatted);
    std::string msg_str(formatted.data(), formatted.size());

    const size_t nb_chunks = (msg_str.size() / BUFFER_SIZE) + 1;

    for (size_t i = 0; i < nb_chunks; ++i) {
      const size_t rem = msg_str.size() - i * BUFFER_SIZE;
      std::string msg = msg_str.substr(i * BUFFER_SIZE,
                                       std::min<size_t>(rem, BUFFER_SIZE));

      if constexpr (std::is_same_v<ErrOrOut, py_stderr_tag>) {
        PySys_WriteStderr("%s", msg.c_str());
      } else {
        PySys_WriteStdout("%s", msg.c_str());
      }
    }
  }
};

using python_stderr_sink_mt = python_base_sink<std::mutex, py_stderr_tag>;
using python_stderr_sink_st = python_base_sink<details::null_mutex, py_stderr_tag>;
} // namespace sinks

template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> stderr_python_mt(const std::string& logger_name)
{
  return Factory::template create<sinks::python_stderr_sink_mt>(logger_name);
}

template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> stderr_python_st(const std::string& logger_name)
{
  return Factory::template create<sinks::python_stderr_sink_st>(logger_name);
}
}
