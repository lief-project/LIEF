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
#include "LIEF/OAT/Binary.hpp"
#include "LIEF/OAT/Class.hpp"
#include "LIEF/OAT/Method.hpp"
#include "LIEF/OAT/DexFile.hpp"
#include "LIEF/DEX/File.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "pyIterator.hpp"

#include "OAT/pyOAT.hpp"

#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::OAT::py {
template<>
void create<Binary>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Binary, ELF::Binary> bin(m, "Binary", "OAT binary representation"_doc);

  init_ref_iterator<Binary::it_dex_files>(bin, "it_dex_files");
  init_ref_iterator<Binary::it_oat_dex_files>(bin, "it_oat_dex_files");
  init_ref_iterator<Binary::it_classes>(bin, "it_classes");
  init_ref_iterator<Binary::it_methods>(bin, "it_methods");

  bin
    .def_prop_ro("header",
        nb::overload_cast<>(&Binary::header),
        "Return the OAT " RST_CLASS_REF(lief.OAT.Header) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("dex_files",
        nb::overload_cast<>(&Binary::dex_files),
        "Return an iterator over " RST_CLASS_REF(lief.DEX.File) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("oat_dex_files",
        nb::overload_cast<>(&Binary::oat_dex_files),
        "Return an iterator over " RST_CLASS_REF(lief.OAT.DexFile) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("classes",
        nb::overload_cast<>(&Binary::classes),
        "Return an iterator over " RST_CLASS_REF(lief.OAT.Class) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("methods",
        nb::overload_cast<>(&Binary::methods),
        "Return an iterator over " RST_CLASS_REF(lief.OAT.Method) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("has_class", &Binary::has_class,
        "Check if the class if the given name is present in the current OAT binary"_doc)

    .def("get_class",
        nb::overload_cast<const std::string&>(&Binary::get_class),
        "Return the " RST_CLASS_REF(lief.OAT.Class) " from its name"_doc,
        "class_name"_a, nb::rv_policy::reference_internal)

    .def("get_class",
        nb::overload_cast<size_t>(&Binary::get_class),
        "Return the " RST_CLASS_REF(lief.OAT.Class) " from its **index**"_doc,
        "class_index"_a, nb::rv_policy::reference_internal)

    .def_prop_ro("dex2dex_json_info", &Binary::dex2dex_json_info)
    LIEF_DEFAULT_STR(Binary);
}

}
