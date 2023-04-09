/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>


namespace LIEF {
namespace PE {

template<>
void create<LoadConfigurationV10>(py::module& m) {
  py::class_<LoadConfigurationV10, LoadConfigurationV9>(m, "LoadConfigurationV10")
    .def(py::init<>())

    .def_property("guard_xfg_check_function_pointer",
        py::overload_cast<>(&LoadConfigurationV10::guard_xfg_check_function_pointer, py::const_),
        py::overload_cast<uint64_t>(&LoadConfigurationV10::guard_xfg_check_function_pointer),
        "")

    .def_property("guard_xfg_dispatch_function_pointer",
        py::overload_cast<>(&LoadConfigurationV10::guard_xfg_dispatch_function_pointer, py::const_),
        py::overload_cast<uint64_t>(&LoadConfigurationV10::guard_xfg_dispatch_function_pointer),
        "")

    .def_property("guard_xfg_table_dispatch_function_pointer",
        py::overload_cast<>(&LoadConfigurationV10::guard_xfg_table_dispatch_function_pointer, py::const_),
        py::overload_cast<uint64_t>(&LoadConfigurationV10::guard_xfg_table_dispatch_function_pointer),
        "")


    .def("__eq__", &LoadConfigurationV10::operator==)
    .def("__ne__", &LoadConfigurationV10::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV10& config) {
          return Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfigurationV10& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });
}

}
}
