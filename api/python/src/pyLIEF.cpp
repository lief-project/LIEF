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
#include "pyLIEF.hpp"
#include "pyErr.hpp"
#include <spdlog/logger.h>
#include "spdlog/sinks/python_sink.h"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "LIEF/hash.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/errors.hpp"
#include "LIEF/logging.hpp"
#include "LIEF/version.h"
#include "LIEF/json.hpp"

#include "platforms/pyPlatform.hpp"

#include "Abstract/init.hpp"

#if defined(LIEF_ELF_SUPPORT)
  #include "ELF/init.hpp"
#endif

#if defined(LIEF_PE_SUPPORT)
  #include "PE/init.hpp"
#endif

#if defined(LIEF_MACHO_SUPPORT)
  #include "MachO/init.hpp"
#endif

#if defined(LIEF_OAT_SUPPORT)
  #include "OAT/init.hpp"
#endif

#if defined(LIEF_DEX_SUPPORT)
  #include "DEX/init.hpp"
#endif

#if defined(LIEF_VDEX_SUPPORT)
  #include "VDEX/init.hpp"
#endif

#if defined(LIEF_ART_SUPPORT)
  #include "ART/init.hpp"
#endif

nb::module_* lief_mod = nullptr;

namespace LIEF::py {
void init_object(nb::module_& m) {
  nb::class_<Object>(m, "Object")
    .def("__hash__", [] (const Object& self) {
        return hash(self);
    })
    .def("__eq__",
        [] (const Object& lhs, const Object& rhs) {
          return hash(lhs) == hash(rhs);
        });
}

void init_python_sink() {
  auto sink = std::make_shared<spdlog::sinks::python_stderr_sink_mt>();
  spdlog::logger logger("LIEF", std::move(sink));
  LIEF::logging::set_logger(std::move(logger));
}

void init_logger(nb::module_& m) {
  nb::module_ logging = m.def_submodule("logging");

  #define PY_ENUM(x) LIEF::logging::to_string(x), x
  nb::enum_<logging::LOGGING_LEVEL>(logging, "LOGGING_LEVEL")
    .value(PY_ENUM(logging::LOGGING_LEVEL::LOG_TRACE))
    .value(PY_ENUM(logging::LOGGING_LEVEL::LOG_DEBUG))
    .value(PY_ENUM(logging::LOGGING_LEVEL::LOG_CRITICAL))
    .value(PY_ENUM(logging::LOGGING_LEVEL::LOG_ERR))
    .value(PY_ENUM(logging::LOGGING_LEVEL::LOG_WARN))
    .value(PY_ENUM(logging::LOGGING_LEVEL::LOG_INFO));
  #undef PY_ENUM

  logging.def("disable", &logging::disable,
              "Disable the logger globally");

  logging.def("enable", &logging::enable,
              "Enable the logger globally");

  logging.def("set_level", &logging::set_level,
              "Change logging level", "level"_a);

  logging.def("set_path", &logging::set_path,
              "Change the logger as a file-base logging and set its path",
              "path"_a);

  logging.def("log", &logging::log,
              "Log a message with the LIEF's logger",
              "level"_a, "msg"_a);

  logging.def("reset", [] {
    logging::reset();
    init_python_sink();
  });
}

void init_hash(nb::module_& m) {
  m.def("hash", nb::overload_cast<const Object&>(&hash));
  m.def("hash", nb::overload_cast<const std::vector<uint8_t>&>(&hash));
  m.def("hash",
        [] (nb::bytes bytes) {
          const auto* begin = reinterpret_cast<const uint8_t*>(bytes.c_str());
          const auto* end = begin + bytes.size();
          return LIEF::hash(std::vector<uint8_t>(begin, end));
        });

  m.def("hash",
        [] (const std::string& bytes) {
          const std::vector<uint8_t> data = {std::begin(bytes), std::end(bytes)};
          return hash(data);
        });
}


void init_json(nb::module_& m) {
  m.def("to_json", &LIEF::to_json);
}

void init(nb::module_& m) {
  lief_mod = &m;
  m.attr("__version__")   = nb::str(LIEF_VERSION);
  m.attr("__tag__")       = nb::str(LIEF_TAG);
  m.attr("__commit__")    = nb::str(LIEF_COMMIT);
  m.attr("__is_tagged__") = bool(LIEF_TAGGED);
  m.doc() = "LIEF Python API";

  m.def("disable_leak_warning", [] {
    nb::set_leak_warnings(false);
  }, R"doc(
  Disable nanobind warnings about leaked objects.
  For instance:

  .. code-block:: text

      nanobind: leaked 45 instances!
      nanobind: leaked 25 types!
       - leaked type "lief._lief.FORMATS"
       - ... skipped remainder
      nanobind: leaked 201 functions!
       - leaked function ""
       - leaked function "export_symbol"
       - ... skipped remainder
      nanobind: this is likely caused by a reference counting issue in the binding code.
  )doc");

  LIEF::py::init_python_sink();

  LIEF::py::init_platforms(m);
  LIEF::py::init_object(m);
  LIEF::py::init_errors(m);
  LIEF::py::init_logger(m);
  LIEF::py::init_hash(m);
  LIEF::py::init_json(m);

  LIEF::py::init_abstract(m);

#if defined(LIEF_ELF_SUPPORT)
  LIEF::ELF::py::init(m);
#endif

#if defined(LIEF_PE_SUPPORT)
  LIEF::PE::py::init(m);
#endif

#if defined(LIEF_MACHO_SUPPORT)
  LIEF::MachO::py::init(m);
#endif

#if defined(LIEF_OAT_SUPPORT)
  LIEF::OAT::py::init(m);
#endif

#if defined(LIEF_DEX_SUPPORT)
  LIEF::DEX::py::init(m);
#endif

#if defined(LIEF_VDEX_SUPPORT)
  LIEF::VDEX::py::init(m);
#endif

#if defined(LIEF_ART_SUPPORT)
  LIEF::ART::py::init(m);
#endif
}
}

NB_MODULE(_lief, m) {
  LIEF::py::init(m);
}
