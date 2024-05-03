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
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/vector.h>

#include "Abstract/init.hpp"
#include "pyLIEF.hpp"

#include "LIEF/Abstract/Function.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

#define PY_ENUM(x) LIEF::to_string(x), x

namespace LIEF::py {

template<>
void create<Function>(nb::module_& m) {
  nb::class_<Function, Symbol> pyfunction(m, "Function",
      R"delim(
      Class which represents a Function in an executable file format.
      )delim"_doc);

  nb::enum_<Function::FLAGS>(pyfunction, "FLAGS")
    .value(PY_ENUM(Function::FLAGS::IMPORTED))
    .value(PY_ENUM(Function::FLAGS::EXPORTED))
    .value(PY_ENUM(Function::FLAGS::CONSTRUCTOR))
    .value(PY_ENUM(Function::FLAGS::DESTRUCTOR))
    .value(PY_ENUM(Function::FLAGS::DEBUG_INFO));

    pyfunction
    .def(nb::init())
    .def(nb::init<const std::string&>())
    .def(nb::init<uint64_t>())
    .def(nb::init<const std::string&, uint64_t>())

    .def("add",
        &Function::add,
        "Add the given " RST_CLASS_REF(lief.Function.FLAGS) ""_doc,
        "flag"_a)

    .def_prop_ro("flags",
        &Function::flags,
        "Function flags as a list of " RST_CLASS_REF(lief.Function.FLAGS) ""_doc)

    .def_prop_rw("address",
        nb::overload_cast<>(&Function::address, nb::const_),
        nb::overload_cast<uint64_t>(&Function::address),
        "Function's address"_doc)

    LIEF_DEFAULT_STR(Function);

}
}
