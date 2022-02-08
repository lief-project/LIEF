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
#include "LIEF/OAT/Binary.hpp"
#include "LIEF/OAT/hash.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "pyIterators.hpp"

#include "pyOAT.hpp"

namespace LIEF {
namespace OAT {

template<class T>
using no_const_getter = T (Binary::*)();

template<class T, class P>
using no_const_func = T (Binary::*)(P);

template<class T>
using getter_t = T (Binary::*)() const;

template<class T>
using setter_t = void (Binary::*)(T);

template<>
void create<Binary>(py::module& m) {

  // Binary object
  py::class_<Binary, ELF::Binary> bin(m, "Binary", "OAT binary representation");

  init_ref_iterator<Binary::it_dex_files>(bin, "it_dex_files");
  init_ref_iterator<Binary::it_oat_dex_files>(bin, "it_oat_dex_files");
  init_ref_iterator<Binary::it_classes>(bin, "it_classes");
  init_ref_iterator<Binary::it_methods>(bin, "it_methods");

  bin
    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&Binary::header),
        "Return the OAT " RST_CLASS_REF(lief.OAT.Header) "",
        py::return_value_policy::reference)

    .def_property_readonly("dex_files",
        static_cast<no_const_getter<Binary::it_dex_files>>(&Binary::dex_files),
        "Return an iterator over " RST_CLASS_REF(lief.DEX.File) "")

    .def_property_readonly("oat_dex_files",
        static_cast<no_const_getter<Binary::it_oat_dex_files>>(&Binary::oat_dex_files),
        "Return an iterator over " RST_CLASS_REF(lief.OAT.DexFile) "")

    .def_property_readonly("classes",
        static_cast<no_const_getter<Binary::it_classes>>(&Binary::classes),
        "Return an iterator over " RST_CLASS_REF(lief.OAT.Class) "",
        py::return_value_policy::reference)

    .def_property_readonly("methods",
        static_cast<no_const_getter<Binary::it_methods>>(&Binary::methods),
        "Return an iterator over " RST_CLASS_REF(lief.OAT.Method) "",
        py::return_value_policy::reference)

    .def_property_readonly("has_class",
        &Binary::has_class,
        "Check if the class if the given name is present in the current OAT binary")

    .def("get_class",
        static_cast<no_const_func<Class*, const std::string&>>(&Binary::get_class),
        "Return the " RST_CLASS_REF(lief.OAT.Class) " from its name",
        "class_name"_a,
        py::return_value_policy::reference)

    .def("get_class",
        static_cast<no_const_func<Class*, size_t>>(&Binary::get_class),
        "Return the " RST_CLASS_REF(lief.OAT.Class) " from its **index**",
        "class_index"_a,
        py::return_value_policy::reference)

    .def_property_readonly("dex2dex_json_info",
        &Binary::dex2dex_json_info)

    .def("__eq__", &Binary::operator==)
    .def("__ne__", &Binary::operator!=)
    .def("__hash__",
        [] (const Binary& bin) {
          return Hash::hash(bin);
        })

    .def("__str__",
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          return stream.str();
        });
}

}
}
