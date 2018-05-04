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
#include "LIEF/DEX/File.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (File::*)(void) const;

template<class T>
using no_const_getter_t = T (File::*)(void);

template<class T>
using setter_t = void (File::*)(T);


template<>
void create<File>(py::module& m) {

  py::class_<File, LIEF::Object>(m, "File", "DEX File representation")

    .def_property_readonly("version",
        &File::version,
        "Dex version")

    .def_property_readonly("header",
        static_cast<no_const_getter_t<Header&>>(&File::header),
        "Dex File " RST_CLASS_REF(lief.DEX.Header) "",
        py::return_value_policy::reference)

    .def_property_readonly("classes",
        static_cast<no_const_getter_t<it_classes>>(&File::classes),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Class) "")

    .def("has_class",
        &File::has_class,
        "Check if a class with a name given in parameter exists",
        "classname"_a)

    .def("get_class",
        static_cast<Class&(File::*)(const std::string&)>(&File::get_class),
        "classname"_a,
        py::return_value_policy::reference)

    .def("get_class",
        static_cast<Class&(File::*)(size_t)>(&File::get_class),
        "classname"_a,
        py::return_value_policy::reference)

    .def_property_readonly("methods",
        static_cast<no_const_getter_t<it_methods>>(&File::methods),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Method) "")

    .def_property_readonly("strings",
        static_cast<no_const_getter_t<it_strings>>(&File::strings),
        "Iterator over Dex strings")

    .def_property_readonly("types",
        static_cast<no_const_getter_t<it_types>>(&File::types),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Type) "")

    .def_property_readonly("prototypes",
        static_cast<no_const_getter_t<it_protypes>>(&File::prototypes),
        "Iterator over Dex " RST_CLASS_REF(lief.DEX.Prototype) "")

    .def_property_readonly("map",
        static_cast<no_const_getter_t<MapList&>>(&File::map),
        "Dex " RST_CLASS_REF(lief.DEX.MapList) "")

    .def("raw",
        &File::raw,
        "Original raw file",
        "deoptimize"_a = true)

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&File::name),
        static_cast<setter_t<const std::string&>>(&File::name),
        "Name of the dex file")

    .def_property("location",
        static_cast<getter_t<const std::string&>>(&File::location),
        static_cast<setter_t<const std::string&>>(&File::location),
        "Original location of the dex file")

    //.def_property_readonly("dex2dex_info",
    //    &File::dex2dex_info)

    .def_property_readonly("dex2dex_json_info",
        &File::dex2dex_json_info)

    .def("save",
        &File::save,
        "Save the **original** file into the file given in first parameter",
        "output"_a = "", "deoptimize"_a = true)

    .def("__eq__", &File::operator==)
    .def("__ne__", &File::operator!=)
    .def("__hash__",
        [] (const File& file) {
          return Hash::hash(file);
        })

    .def("__str__",
        [] (const File& file) {
          std::ostringstream stream;
          stream << file;
          return stream.str();
        });
}

}
}
