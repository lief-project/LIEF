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

#include "DEX/pyDEX.hpp"

#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/Field.hpp"
#include "LIEF/DEX/Method.hpp"

#include "pyIterator.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unordered_map.h>

namespace LIEF::DEX::py {

template<>
void create<Class>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Class, LIEF::Object> cls(m, "Class", "DEX Class representation"_doc);

  init_ref_iterator<Class::it_methods>(cls, "it_methods");
  init_ref_iterator<Class::it_fields>(cls, "it_fields");

  init_ref_iterator<Class::it_named_methods>(cls, "it_named_methods");
  init_ref_iterator<Class::it_named_fields>(cls, "it_named_fields");

  cls
    .def_prop_ro("fullname", &Class::fullname,
        "Mangled class name (e.g. ``Lcom/example/android/MyActivity;``)"_doc)

    .def_prop_ro("pretty_name", &Class::pretty_name,
        "Demangled class name (e.g. ``com.example.android.MyActivity``)"_doc)

    .def_prop_ro("name", &Class::name,
        "Class name (e.g. ``MyActivity``)"_doc)

    .def_prop_ro("source_filename", &Class::source_filename,
        "Original filename"_doc)

    .def_prop_ro("package_name", &Class::package_name,
        "Package Name (e.g. ``com.example.android``)"_doc)

    .def_prop_ro("has_parent", &Class::has_parent,
        "True if the current class extends another one"_doc)

    .def_prop_ro("parent", nb::overload_cast<>(&Class::parent),
        "" RST_CLASS_REF(lief.DEX.Class) " parent class"_doc)

    .def_prop_ro("methods", nb::overload_cast<>(&Class::methods),
        "Iterator over " RST_CLASS_REF(lief.DEX.Method) " implemented in this class"_doc)

    .def("get_method", nb::overload_cast<const std::string&>(&Class::methods),
        "Iterator over " RST_CLASS_REF(lief.DEX.Method) " (s) having the given name"_doc,
        "name"_a)

    .def_prop_ro("fields", nb::overload_cast<>(&Class::fields),
        "Iterator over " RST_CLASS_REF(lief.DEX.Field) " in this class"_doc)

    .def("get_field", nb::overload_cast<const std::string&>(&Class::fields),
        "Iterator over " RST_CLASS_REF(lief.DEX.Field) " (s) having the given name"_doc,
        "name"_a)

    .def_prop_ro("access_flags",
        nb::overload_cast<>(&Class::access_flags, nb::const_),
        "List of " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) ""_doc)

    .def_prop_ro("dex2dex_info", &Class::dex2dex_info,
        "De-optimize information"_doc)

    .def_prop_ro("index", &Class::index,
        "Original index in the DEX class pool"_doc)

    .def("has", nb::overload_cast<ACCESS_FLAGS>(&Class::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) " is present"_doc,
        "flag"_a)

    LIEF_DEFAULT_STR(Class);
}
}
