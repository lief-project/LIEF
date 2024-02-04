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
#include "LIEF/OAT/Method.hpp"
#include "LIEF/OAT/Class.hpp"
#include "LIEF/DEX/Method.hpp"

#include "OAT/pyOAT.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::OAT::py {

template<>
void create<Method>(nb::module_& m) {

  nb::class_<Method, Object>(m, "Method", "OAT Method representation"_doc)
    .def(nb::init<>())

    .def_prop_ro("name", &Method::name,
        "Method's name"_doc)

    .def_prop_ro("oat_class",
        nb::overload_cast<>(&Method::oat_class),
        "" RST_CLASS_REF(lief.OAT.Class) " associated with the method (or None)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("dex_method",
        nb::overload_cast<>(&Method::dex_method),
        "Mirrored " RST_CLASS_REF(lief.DEX.Method) " associated with the OAT method (or None)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dex_method",
        &Method::has_dex_method,
        "Check if a  " RST_CLASS_REF(lief.DEX.Method) " is associated with the OAT method"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("is_dex2dex_optimized", &Method::is_dex2dex_optimized,
        "True if the optimization is **DEX**"_doc)

    .def_prop_ro("is_compiled", &Method::is_compiled,
        "True if the optimization is **native**"_doc)

    .def_prop_rw("quick_code",
        nb::overload_cast<>(&Method::quick_code, nb::const_),
        nb::overload_cast<const Method::quick_code_t&>(&Method::quick_code),
        "Quick code associated with the method"_doc)

    LIEF_DEFAULT_STR(Method);
}
}
