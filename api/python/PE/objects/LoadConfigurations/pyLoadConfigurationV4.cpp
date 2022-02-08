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
using getter_t = T (LoadConfigurationV4::*)(void) const;

template<class T>
using setter_t = void (LoadConfigurationV4::*)(T);


template<>
void create<LoadConfigurationV4>(py::module& m) {
  py::class_<LoadConfigurationV4, LoadConfigurationV3>(m, "LoadConfigurationV4",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV3` enhanced with:

        * Kind of dynamic relocations
        * *Hybrid Metadata Pointer*

      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN10_0_14383`
      )delim")
    .def(py::init<>())

    .def_property("dynamic_value_reloc_table",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV4::dynamic_value_reloc_table),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV4::dynamic_value_reloc_table),
        "VA of pointing to a ``IMAGE_DYNAMIC_RELOCATION_TABLE``")

    .def_property("hybrid_metadata_pointer",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV4::hybrid_metadata_pointer),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV4::hybrid_metadata_pointer),
        "")


    .def("__eq__", &LoadConfigurationV4::operator==)
    .def("__ne__", &LoadConfigurationV4::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV4& config) {
          return Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfigurationV4& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });
}

}
}
