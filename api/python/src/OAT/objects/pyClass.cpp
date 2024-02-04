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
#include "LIEF/OAT/Class.hpp"
#include "LIEF/OAT/Method.hpp"
#include "LIEF/DEX/Method.hpp"

#include "pyIterator.hpp"
#include "OAT/pyOAT.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::OAT::py {

template<>
void create<Class>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Class, Object> cls(m, "Class", "OAT Class representation"_doc);

  init_ref_iterator<Class::it_methods>(cls, "it_methods");

  cls
    .def(nb::init<>())

    .def("has_dex_class", &Class::has_dex_class,
        "True if a " RST_CLASS_REF_FULL(lief.DEX.Class) " object "
        "is associated with this **OAT** Class"_doc)

    .def_prop_ro("status", &Class::status,
        "Class " RST_CLASS_REF(lief.OAT.OAT_CLASS_STATUS) ""_doc)

    .def_prop_ro("type", &Class::type,
        "Information (" RST_CLASS_REF(lief.OAT.OAT_CLASS_TYPES) ") about how methods "
        "are optimized"_doc)

    .def_prop_ro("fullname", &Class::fullname,
        "Class mangled name (e.g. ``Lcom/android/MyActivity;``)"_doc)

    .def_prop_ro("index", &Class::index,
        "Index the **DEX** classes pool (" RST_ATTR_REF_FULL(lief.DEX.File.classes) ")"_doc)

    .def_prop_ro("methods", nb::overload_cast<>(&Class::methods),
        "Iterator over " RST_CLASS_REF_FULL(lief.OAT.Method) ""_doc)

    .def_prop_ro("bitmap", &Class::bitmap,
        "Bitmap information used to quickly find which methods are "
        "optimized"_doc)

    .def("is_quickened",
        nb::overload_cast<const LIEF::DEX::Method&>(&Class::is_quickened, nb::const_),
        "Check if the given " RST_CLASS_REF_FULL(lief.DEX.Method) " is compiled into native code"_doc,
        "dex_method"_a)

    .def("is_quickened",
        nb::overload_cast<uint32_t>(&Class::is_quickened, nb::const_),
        "Check if the Method at the given index is compiled into native code"_doc,
        "method_index"_a)

    .def("method_offsets_index",
        nb::overload_cast<const DEX::Method&>(&Class::method_offsets_index, nb::const_))

    .def("method_offsets_index",
        nb::overload_cast<uint32_t>(&Class::method_offsets_index, nb::const_))

    LIEF_DEFAULT_STR(Class);
}

}
