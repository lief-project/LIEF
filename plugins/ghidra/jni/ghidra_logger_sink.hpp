/* Copyright 2022 - 2026 R. Thomas
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

#include <spdlog/details/fmt_helper.h>
#include <spdlog/details/null_mutex.h>
#include <spdlog/details/os.h>
#include <spdlog/sinks/base_sink.h>
#include <spdlog/details/synchronous_factory.h>

#include <ghidra/util/Msg.hpp>

namespace spdlog {
namespace sinks {

template<typename Mutex>
class ghidra_sink final : public base_sink<Mutex>
{
public:
    explicit ghidra_sink(std::string tag, bool use_raw_msg = true)
        : tag_(std::move(tag)), use_raw_msg_(use_raw_msg)
    {}

protected:
    void sink_it_(const details::log_msg &msg) override
    {
        memory_buf_t formatted;
        if (use_raw_msg_)
        {
            details::fmt_helper::append_string_view(msg.payload, formatted);
        }
        else
        {
            base_sink<Mutex>::formatter_->format(msg, formatted);
        }
        formatted.push_back('\0');
        const char *msg_output = formatted.data();

        switch (msg.level) {
          case spdlog::level::trace:
            return ghidra::util::Msg::trace(tag_, formatted.data());
          case spdlog::level::debug:
            return ghidra::util::Msg::debug(tag_, formatted.data());
          case spdlog::level::info:
            return ghidra::util::Msg::info(tag_, formatted.data());
          case spdlog::level::warn:
            return ghidra::util::Msg::warn(tag_, formatted.data());
          case spdlog::level::err:
          case spdlog::level::critical:
            return ghidra::util::Msg::error(tag_, formatted.data());
          default:
            return;
        }
    }

    void flush_() override {}

private:
    std::string tag_;
    bool use_raw_msg_;
};

using ghidra_sink_mt = ghidra_sink<std::mutex>;
using ghidra_sink_st = ghidra_sink<details::null_mutex>;

using ghidra_sink_buf_mt = ghidra_sink<std::mutex>;
using ghidra_sink_buf_st = ghidra_sink<details::null_mutex>;

} // namespace sinks

// Create and register Ghidra sink
template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> ghidra_logger_mt(const std::string &logger_name, const std::string &tag = "spdlog")
{
    return Factory::template create<sinks::ghidra_sink_mt>(logger_name, tag);
}

template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> ghidra_logger_st(const std::string &logger_name, const std::string &tag = "spdlog")
{
    return Factory::template create<sinks::ghidra_sink_st>(logger_name, tag);
}
}
