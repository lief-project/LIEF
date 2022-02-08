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
#include "pyLIEF.hpp"

#include "LIEF/logging.hpp"

#define PY_ENUM(x) LIEF::logging::to_string(x), x

void init_LIEF_Logger(py::module& m) {
  py::module logging = m.def_submodule("logging");

  py::enum_<LIEF::logging::LOGGING_LEVEL>(logging, "LOGGING_LEVEL")
    .value(PY_ENUM(LIEF::logging::LOGGING_LEVEL::LOG_TRACE))
    .value(PY_ENUM(LIEF::logging::LOGGING_LEVEL::LOG_DEBUG))
    .value(PY_ENUM(LIEF::logging::LOGGING_LEVEL::LOG_CRITICAL))
    .value(PY_ENUM(LIEF::logging::LOGGING_LEVEL::LOG_ERR))
    .value(PY_ENUM(LIEF::logging::LOGGING_LEVEL::LOG_WARN))
    .value(PY_ENUM(LIEF::logging::LOGGING_LEVEL::LOG_INFO));

  logging.def("disable",
      &LIEF::logging::disable,
      "Disable the logger globally");

  logging.def("enable",
      &LIEF::logging::enable,
      "Enable the logger globally");

  logging.def("set_level",
      &LIEF::logging::set_level,
      "Change logging level",
      "level"_a);
}
