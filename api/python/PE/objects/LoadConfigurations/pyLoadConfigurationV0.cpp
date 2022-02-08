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
using getter_t = T (LoadConfigurationV0::*)(void) const;

template<class T>
using setter_t = void (LoadConfigurationV0::*)(T);


template<>
void create<LoadConfigurationV0>(py::module& m) {
  py::class_<LoadConfigurationV0, LoadConfiguration>(m, "LoadConfigurationV0",
    R"delim(
    :class:`~lief.PE.LoadConfiguration` enhanced with SEH.
    It is associated with the :class:`~lief.PE.WIN_VERSION`: :attr:`~lief.PE.WIN_VERSION.SEH`
    )delim")

    .def(py::init<>())

    .def_property("se_handler_table",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV0::se_handler_table),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV0::se_handler_table),
        "The VA of the sorted table of RVAs of each valid, unique "
        "SE handler in the image.")

    .def_property("se_handler_count",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV0::se_handler_count),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV0::se_handler_count),
        "The count of unique handlers in the table.")


    .def("__eq__", &LoadConfigurationV0::operator==)
    .def("__ne__", &LoadConfigurationV0::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV0& config) {
          return Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfigurationV0& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });
}

}
}
