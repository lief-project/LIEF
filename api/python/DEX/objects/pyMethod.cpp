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
#include "LIEF/DEX/Method.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (Method::*)(void) const;

template<class T>
using no_const_getter_t = T (Method::*)(void);

template<class T>
using setter_t = void (Method::*)(T);


template<>
void create<Method>(py::module& m) {

  py::class_<Method, LIEF::Object>(m, "Method", "DEX Method representation")
    .def_property_readonly("name",
        &Method::name,
        "Method's name")

    .def_property_readonly("index",
        &Method::index,
        "Original DEX file index of the method")

    .def_property_readonly("has_class",
        &Method::has_class,
        "True if a class is associated with this method")

    .def_property_readonly("cls",
        static_cast<no_const_getter_t<Class*>>(&Method::cls),
        "" RST_CLASS_REF(lief.DEX.Class) " associated with this method")

    .def_property_readonly("code_offset",
        static_cast<getter_t<uint64_t>>(&Method::code_offset),
        "Offset to the Dalvik Bytecode")

    .def_property_readonly("bytecode",
        static_cast<getter_t<const Method::bytecode_t&>>(&Method::bytecode),
        "Dalvik Bytecode as a list of bytes")

    .def_property_readonly("is_virtual",
        &Method::is_virtual,
        "True if the method is a virtual (not **private**, **static**, **final**, **constructor**)")

    .def_property_readonly("prototype",
        static_cast<no_const_getter_t<Prototype*>>(&Method::prototype),
        "" RST_CLASS_REF(lief.DEX.Prototype) " of this method")

    .def_property_readonly("access_flags",
        static_cast<getter_t<Method::access_flags_list_t>>(&Method::access_flags),
        "List of " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) "")

    .def("has",
        static_cast<bool(Method::*)(ACCESS_FLAGS) const>(&Method::has),
        "Check if the given " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) " is present",
        "flag"_a)

    .def("insert_dex2dex_info",
        &Method::insert_dex2dex_info,
        "Insert de-optimization information",
        "pc"_a, "index"_a)

    .def("__eq__", &Method::operator==)
    .def("__ne__", &Method::operator!=)
    .def("__hash__",
        [] (const Method& cls) {
          return Hash::hash(cls);
        })

    .def("__str__",
        [] (const Method& cls) {
          std::ostringstream stream;
          stream << cls;
          return stream.str();
        });
}

}
}
