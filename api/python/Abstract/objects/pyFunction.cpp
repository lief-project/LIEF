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
#include "pyAbstract.hpp"
#include "LIEF/Abstract/Symbol.hpp"

#include <string>
#include <sstream>

#define PY_ENUM(x) LIEF::to_string(x), x

namespace LIEF {

template<class T>
using getter_t = T (Function::*)(void) const;

template<class T>
using setter_t = void (Function::*)(T);

template<>
void create<Function>(py::module& m) {

  py::class_<Function, Symbol> pyfunction(m, "Function",
      R"delim(
      Class which represents a Function in an executable file format.
      )delim");

  py::enum_<Function::FLAGS>(pyfunction, "FLAGS")
    .value(PY_ENUM(Function::FLAGS::IMPORTED))
    .value(PY_ENUM(Function::FLAGS::EXPORTED))
    .value(PY_ENUM(Function::FLAGS::CONSTRUCTOR))
    .value(PY_ENUM(Function::FLAGS::DESTRUCTOR))
    .value(PY_ENUM(Function::FLAGS::DEBUG));

    pyfunction
    .def(py::init())
    .def(py::init<const std::string&>())
    .def(py::init<uint64_t>())
    .def(py::init<const std::string&, uint64_t>())

    .def("add",
        &Function::add,
        "Add the given " RST_CLASS_REF(lief.Function.FLAGS) "",
        "flag"_a)

    .def_property_readonly("flags",
        &Function::flags,
        "Function flags as a list of " RST_CLASS_REF(lief.Function.FLAGS) "")

    .def_property("address",
        static_cast<getter_t<uint64_t>>(&Function::address),
        static_cast<setter_t<uint64_t>>(&Function::address),
        "Function's address")

    .def("__str__",
        [] (const Function& f) {
          std::ostringstream stream;
          stream << f;
          std::string str = stream.str();
          return str;
        });
}

}
