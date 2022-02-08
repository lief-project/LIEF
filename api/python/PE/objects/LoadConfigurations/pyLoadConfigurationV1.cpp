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
using getter_t = T (LoadConfigurationV1::*)(void) const;

template<class T>
using setter_t = void (LoadConfigurationV1::*)(T);


template<>
void create<LoadConfigurationV1>(py::module& m) {
  py::class_<LoadConfigurationV1, LoadConfigurationV0>(m, "LoadConfigurationV1",
      R"delim(
      :class:`~lief.PE.LoadConfigurationV0` enhanced with *Control Flow Guard*.
      It is associated with the :class:`~lief.PE.WIN_VERSION` set to :attr:`~lief.PE.WIN_VERSION.WIN_8_1`
      )delim")
    .def(py::init<>())

    .def_property("guard_cf_check_function_pointer",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_check_function_pointer),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_check_function_pointer),
        "The VA where Control Flow Guard check-function pointer is stored.")

    .def_property("guard_cf_dispatch_function_pointer",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_dispatch_function_pointer),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_dispatch_function_pointer),
        "The VA where Control Flow Guard dispatch-function pointer is stored.")

    .def_property("guard_cf_function_table",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_function_table),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_function_table),
        "The VA of the sorted table of RVAs of each Control Flow Guard function in the image.")

    .def_property("guard_cf_function_count",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_function_count),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV1::guard_cf_function_count),
        "The count of unique RVAs in the :attr:`~lief.PE.LoadConfigurationV1.guard_cf_function_table`")

    .def_property("guard_flags",
        static_cast<getter_t<GUARD_CF_FLAGS>>(&LoadConfigurationV1::guard_flags),
        static_cast<setter_t<GUARD_CF_FLAGS>>(&LoadConfigurationV1::guard_flags),
        "Control Flow Guard related flags.")

    .def("has",
        static_cast<bool (LoadConfigurationV1::*)(GUARD_CF_FLAGS) const>(&LoadConfigurationV1::has),
        "Check if the given " RST_CLASS_REF(lief.PE.GUARD_CF_FLAGS) " is present in "
        ":attr:`~lief.PE.LoadConfigurationV1.guard_flags`",
        "flag"_a)

    .def_property_readonly("guard_cf_flags_list",
        &LoadConfigurationV1::guard_cf_flags_list,
        "Return list of " RST_CLASS_REF(lief.PE.GUARD_CF_FLAGS) " present in "
        ":attr:`~lief.PE.LoadConfigurationV1.guard_flags`",
        py::return_value_policy::reference_internal)

    .def("__eq__", &LoadConfigurationV1::operator==)
    .def("__ne__", &LoadConfigurationV1::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV1& config) {
          return Hash::hash(config);
        })


    .def("__contains__",
        static_cast<bool (LoadConfigurationV1::*)(GUARD_CF_FLAGS) const>(&LoadConfigurationV1::has))


    .def("__str__", [] (const LoadConfigurationV1& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });
}

}
}
