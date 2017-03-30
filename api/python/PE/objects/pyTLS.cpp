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
#include "pyPE.hpp"

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/PE/TLS.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (TLS::*)(void) const;

template<class T>
using setter_t = void (TLS::*)(T);

template<class T>
using no_const_getter = T (TLS::*)(void);

void init_PE_TLS_class(py::module& m) {
  py::class_<TLS>(m, "TLS")
    .def(py::init<>())

    .def_property("callbacks",
        static_cast<getter_t<const std::vector<uint64_t>&>>(&TLS::callbacks),
        static_cast<setter_t<const std::vector<uint64_t>&>>(&TLS::callbacks))

    .def_property("addressof_index",
        static_cast<getter_t<uint64_t>>(&TLS::addressof_index),
        static_cast<setter_t<uint64_t>>(&TLS::addressof_index))

    .def_property("addressof_callbacks",
        static_cast<getter_t<uint64_t>>(&TLS::addressof_callbacks),
        static_cast<setter_t<uint64_t>>(&TLS::addressof_callbacks))

    .def_property("sizeof_zero_fill",
        static_cast<getter_t<uint32_t>>(&TLS::sizeof_zero_fill),
        static_cast<setter_t<uint32_t>>(&TLS::sizeof_zero_fill))

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&TLS::characteristics),
        static_cast<setter_t<uint32_t>>(&TLS::characteristics))

    .def_property("addressof_raw_data",
        static_cast<getter_t<std::pair<uint64_t, uint64_t>>>(&TLS::addressof_raw_data),
        static_cast<setter_t<std::pair<uint64_t, uint64_t>>>(&TLS::addressof_raw_data))

    .def_property("data_template",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&TLS::data_template),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&TLS::data_template))

    .def_property_readonly("directory",
        static_cast<no_const_getter<DataDirectory&>>(&TLS::directory),
        py::return_value_policy::reference)

    .def_property_readonly("section",
        static_cast<no_const_getter<Section&>>(&TLS::section),
        py::return_value_policy::reference)


    .def("__eq__", &TLS::operator==)
    .def("__ne__", &TLS::operator!=)
    .def("__hash__",
        [] (const TLS& tls) {
          return LIEF::Hash::hash(tls);
        })

    .def("__str__", [] (const TLS& tls)
        {
          std::ostringstream stream;
          stream << tls;
          std::string str = stream.str();
          return str;
        });


}
