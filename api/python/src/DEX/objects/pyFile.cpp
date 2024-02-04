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
#include "LIEF/DEX/File.hpp"
#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/Method.hpp"
#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/Prototype.hpp"
#include "LIEF/DEX/Field.hpp"

#include "pyIterator.hpp"
#include "DEX/pyDEX.hpp"

#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::DEX::py {

template<>
void create<File>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<File, Object> file(m, "File", "DEX File representation"_doc);

  init_ref_iterator<File::it_classes>(file, "it_classes");
  init_ref_iterator<File::it_methods>(file, "it_methods");
  init_ref_iterator<File::it_strings>(file, "it_strings");
  init_ref_iterator<File::it_types>(file, "it_types");
  init_ref_iterator<File::it_prototypes>(file, "it_prototypes");
  init_ref_iterator<File::it_fields>(file, "it_fields");

  file
    .def_prop_ro("version", &File::version,
        "Dex version"_doc)

    .def_prop_ro("header", nb::overload_cast<>(&File::header, nb::const_),
        "Dex File " RST_CLASS_REF(lief.DEX.Header) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("classes", nb::overload_cast<>(&File::classes),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Class) ""_doc,
        nb::keep_alive<0, 1>())

    .def("has_class", &File::has_class,
        "Check if a class with a name given in parameter exists"_doc,
        "classname"_a)

    .def("get_class",
        nb::overload_cast<const std::string&>(&File::get_class),
        "classname"_a, nb::rv_policy::reference_internal)

    .def("get_class",
        nb::overload_cast<size_t>(&File::get_class),
        "classname"_a, nb::rv_policy::reference_internal)

    .def_prop_ro("methods", nb::overload_cast<>(&File::methods),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Method) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("fields", nb::overload_cast<>(&File::fields),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Field) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("strings", nb::overload_cast<>(&File::strings),
        "Iterator over Dex strings"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("types", nb::overload_cast<>(&File::types),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Type) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("prototypes",
        nb::overload_cast<>(&File::prototypes),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Prototype) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("map", nb::overload_cast<>(&File::map, nb::const_),
        "Dex " RST_CLASS_REF(lief.DEX.MapList) ""_doc)

    .def("raw", &File::raw,
        "Original raw file"_doc,
        "deoptimize"_a = true)

    .def_prop_rw("name",
        nb::overload_cast<>(&File::name, nb::const_),
        nb::overload_cast<const std::string&>(&File::name),
        "Name of the dex file"_doc)

    .def_prop_rw("location",
        nb::overload_cast<>(&File::location, nb::const_),
        nb::overload_cast<const std::string&>(&File::location),
        "Original location of the dex file"_doc)

    //.def_prop_ro("dex2dex_info",
    //    &File::dex2dex_info)

    .def_prop_ro("dex2dex_json_info",
        &File::dex2dex_json_info)

    .def("save", &File::save,
        "Save the **original** file into the file given in first parameter"_doc,
        "output"_a = "", "deoptimize"_a = true)

    LIEF_DEFAULT_STR(File);
}

}
