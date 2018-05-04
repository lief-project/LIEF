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
#include "LIEF/OAT/Class.hpp"
#include "LIEF/OAT/hash.hpp"

#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

template<class T>
using getter_t = T (Class::*)(void) const;

template<class T>
using setter_t = void (Class::*)(T);

template<class T>
using no_const_getter = T (Class::*)(void);

template<>
void create<Class>(py::module& m) {

  py::class_<Class, LIEF::Object>(m, "Class", "OAT Class representation")
    .def(py::init<>())

    .def("has_dex_class",
        &Class::has_dex_class)

    .def_property_readonly("status",
        &Class::status)

    .def_property_readonly("type",
        &Class::type)

    .def_property_readonly("fullname",
        &Class::fullname)

    .def_property_readonly("index",
        &Class::index)

    .def_property_readonly("methods",
        static_cast<no_const_getter<it_methods>>(&Class::methods))

    .def_property_readonly("bitmap",
        &Class::bitmap)

    .def("is_quickened",
        static_cast<bool(Class::*)(const LIEF::DEX::Method&) const>(&Class::is_quickened))

    .def("is_quickened",
        static_cast<bool(Class::*)(uint32_t relative_index) const>(&Class::is_quickened))

    .def("method_offsets_index",
        static_cast<uint32_t(Class::*)(const LIEF::DEX::Method&) const>(&Class::method_offsets_index))

    .def("method_offsets_index",
        static_cast<uint32_t(Class::*)(uint32_t relative_index) const>(&Class::method_offsets_index))

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
