/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "pyLIEF.hpp"

#include "LIEF/logging.hpp"

#define PY_ENUM(x) LIEF::to_string(x), x

void init_LIEF_Logger(py::module& m) {

  py::enum_<LIEF::LOGGING_LEVEL>(m, "LOGGING_LEVEL")
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_GLOBAL))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_TRACE))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_DEBUG))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_FATAL))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_ERROR))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_WARNING))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_INFO))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_VERBOSE))
    .value(PY_ENUM(LIEF::LOGGING_LEVEL::LOG_UNKNOWN))
    .export_values();

  py::class_<LIEF::Logger>(m, "Logger")
    .def_static("disable",
        &LIEF::Logger::disable,
        "Disable the logging module")

    .def_static("enable",
        &LIEF::Logger::enable,
        "Enable the logging module")

    .def_static("set_level",
        &LIEF::Logger::set_level,
        "Change the " RST_CLASS_REF(lief.LOGGING_LEVEL) " (**hierarchical**)",
        "level"_a)

    .def_static("set_verbose_level",
        &LIEF::Logger::set_verbose_level,
        "Change the verbose level",
        "level"_a);
}
