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
#include "LIEF/DEX/Method.hpp"
#include "LIEF/DEX/Prototype.hpp"
#include "LIEF/DEX/Class.hpp"

#include "DEX/pyDEX.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::DEX::py {

template<>
void create<Method>(nb::module_& m) {

  nb::class_<Method, LIEF::Object>(m, "Method", "DEX Method representation"_doc)
    .def_prop_ro("name", &Method::name,
        "Method's name"_doc)

    .def_prop_ro("index", &Method::index,
        "Original DEX file index of the method"_doc)

    .def_prop_ro("has_class", &Method::has_class,
        "True if a class is associated with this method"_doc)

    .def_prop_ro("cls", nb::overload_cast<>(&Method::cls, nb::const_),
        "" RST_CLASS_REF(lief.DEX.Class) " associated with this method"_doc)

    .def_prop_ro("code_offset", nb::overload_cast<>(&Method::code_offset, nb::const_),
        "Offset to the Dalvik Bytecode"_doc)

    .def_prop_ro("bytecode", nb::overload_cast<>(&Method::bytecode, nb::const_),
        "Dalvik Bytecode as a list of bytes"_doc)

    .def_prop_ro("is_virtual", &Method::is_virtual,
        "True if the method is a virtual (not **private**, **static**, **final**, **constructor**)"_doc)

    .def_prop_ro("prototype",
        nb::overload_cast<>(&Method::prototype, nb::const_),
        "" RST_CLASS_REF(lief.DEX.Prototype) " of this method"_doc)

    .def_prop_ro("access_flags",
        nb::overload_cast<>(&Method::access_flags, nb::const_),
        "List of " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) ""_doc)

    .def("has", nb::overload_cast<ACCESS_FLAGS>(&Method::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) " is present"_doc,
        "flag"_a)

    .def("insert_dex2dex_info", &Method::insert_dex2dex_info,
        "Insert de-optimization information"_doc,
        "pc"_a, "index"_a)

    LIEF_DEFAULT_STR(Method);
}

}
