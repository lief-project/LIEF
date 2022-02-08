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
#include "LIEF/OAT/Method.hpp"
#include "LIEF/OAT/hash.hpp"

#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

template<class T>
using getter_t = T (Method::*)(void) const;

template<class T>
using setter_t = void (Method::*)(T);

template<class T>
using no_const_getter = T (Method::*)(void);

template<>
void create<Method>(py::module& m) {

  py::class_<Method, LIEF::Object>(m, "Method", "OAT Method representation")
    .def(py::init<>())

    .def_property_readonly("name",
        &Method::name,
        "Method's name")

    .def_property_readonly("oat_class",
        static_cast<no_const_getter<Class*>>(&Method::oat_class),
        "" RST_CLASS_REF(lief.OAT.Class) " associated with the method (or None)",
        py::return_value_policy::reference)

    .def_property_readonly("dex_method",
        static_cast<no_const_getter<LIEF::DEX::Method*>>(&Method::dex_method),
        "Mirrored " RST_CLASS_REF(lief.DEX.Method) " associated with the OAT method (or None)",
        py::return_value_policy::reference)

    .def_property_readonly("has_dex_method",
        &Method::has_dex_method,
        "Check if a  " RST_CLASS_REF(lief.DEX.Method) " is associated with the OAT method",
        py::return_value_policy::reference)

    .def_property_readonly("is_dex2dex_optimized",
        &Method::is_dex2dex_optimized,
        "True if the optimization is **DEX**")

    .def_property_readonly("is_compiled",
        &Method::is_compiled,
        "True if the optimization is **native**")

    .def_property("quick_code",
        static_cast<getter_t<const Method::quick_code_t&>>(&Method::quick_code),
        static_cast<setter_t<const Method::quick_code_t&>>(&Method::quick_code),
        "Quick code associated with the method")

    .def("__eq__", &Method::operator==)
    .def("__ne__", &Method::operator!=)
    .def("__hash__",
        [] (const Method& method) {
          return Hash::hash(method);
        })

    .def("__str__",
        [] (const Method& method) {
          std::ostringstream stream;
          stream << method;
          return stream.str();
        });
}

}
}
