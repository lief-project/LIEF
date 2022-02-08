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
#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyIterators.hpp"
#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (Class::*)(void) const;

template<class T>
using no_const_getter_t = T (Class::*)(void);

template<class T>
using setter_t = void (Class::*)(T);


template<>
void create<Class>(py::module& m) {

  py::class_<Class, LIEF::Object> cls(m, "Class", "DEX Class representation");

  init_ref_iterator<Class::it_methods>(cls, "it_methods");
  init_ref_iterator<Class::it_fields>(cls, "it_fields");

  init_ref_iterator<Class::it_named_methods>(cls, "it_named_methods");
  init_ref_iterator<Class::it_named_fields>(cls, "it_named_fields");

  cls
    .def_property_readonly("fullname",
        &Class::fullname,
        "Mangled class name (e.g. ``Lcom/example/android/MyActivity;``)")

    .def_property_readonly("pretty_name",
        &Class::pretty_name,
        "Demangled class name (e.g. ``com.example.android.MyActivity``)")

    .def_property_readonly("name",
        &Class::name,
        "Class name (e.g. ``MyActivity``)")

    .def_property_readonly("source_filename",
        &Class::source_filename,
        "Original filename")

    .def_property_readonly("package_name",
        &Class::package_name,
        "Package Name (e.g. ``com.example.android``)")

    .def_property_readonly("has_parent",
        &Class::has_parent,
        "True if the current class extends another one")

    .def_property_readonly("parent",
        static_cast<no_const_getter_t<Class*>>(&Class::parent),
        "" RST_CLASS_REF(lief.DEX.Class) " parent class")

    .def_property_readonly("methods",
        static_cast<no_const_getter_t<Class::it_methods>>(&Class::methods),
        "Iterator over " RST_CLASS_REF(lief.DEX.Method) " implemented in this class")

    .def("get_method",
        static_cast<Class::it_named_methods(Class::*)(const std::string&)>(&Class::methods),
        "Iterator over " RST_CLASS_REF(lief.DEX.Method) " (s) having the given name",
        "name"_a)

    .def_property_readonly("fields",
        static_cast<no_const_getter_t<Class::it_fields>>(&Class::fields),
        "Iterator over " RST_CLASS_REF(lief.DEX.Field) " in this class")

    .def("get_field",
        static_cast<Class::it_named_fields(Class::*)(const std::string&)>(&Class::fields),
        "Iterator over " RST_CLASS_REF(lief.DEX.Field) " (s) having the given name",
        "name"_a)

    .def_property_readonly("access_flags",
        static_cast<getter_t<Class::access_flags_list_t>>(&Class::access_flags),
        "List of " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) "")

    .def_property_readonly("dex2dex_info",
        &Class::dex2dex_info,
        "De-optimize information")

    .def_property_readonly("index",
        &Class::index,
        "Original index in the DEX class pool")

    .def("has",
        static_cast<bool(Class::*)(ACCESS_FLAGS) const>(&Class::has),
        "Check if the given " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) " is present",
        "flag"_a)


    .def("__eq__", &Class::operator==)
    .def("__ne__", &Class::operator!=)
    .def("__hash__",
        [] (const Class& cls) {
          return Hash::hash(cls);
        })

    .def("__str__",
        [] (const Class& cls) {
          std::ostringstream stream;
          stream << cls;
          return stream.str();
        });
}

}
}
