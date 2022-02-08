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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>


namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (LoadConfigurationV7::*)(void) const;

template<class T>
using setter_t = void (LoadConfigurationV7::*)(T);

template<>
void create<LoadConfigurationV7>(py::module& m) {
  py::class_<LoadConfigurationV7, LoadConfigurationV6>(m, "LoadConfigurationV7")
    .def(py::init<>())

    .def_property("reserved3",
        static_cast<getter_t<uint32_t>>(&LoadConfigurationV7::reserved3),
        static_cast<setter_t<uint32_t>>(&LoadConfigurationV7::reserved3),
        "")

    .def_property("addressof_unicode_string",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV7::addressof_unicode_string),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV7::addressof_unicode_string),
        "")


    .def("__eq__", &LoadConfigurationV7::operator==)
    .def("__ne__", &LoadConfigurationV7::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV7& config) {
          return Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfigurationV7& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });
}

}
}
