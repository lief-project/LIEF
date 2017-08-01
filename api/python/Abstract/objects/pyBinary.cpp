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
#include "init.hpp"
#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/ELF/Binary.hpp"

#include <algorithm>

using namespace LIEF;

template<class T>
using getter_t = T (Binary::*)(void) const;

template<class T>
using setter_t = void (Binary::*)(T);

template<class T>
using it_t = T (Binary::*)(void);

void init_LIEF_Binary_class(py::module& m) {
  py::class_<Binary>(m, "Binary")

    .def_property_readonly("format",
        &Binary::format,
        "File format " RST_CLASS_REF(lief.EXE_FORMATS) " of the underlying binary.")

    .def_property_readonly("is_pie",
        &Binary::is_pie,
        "Check if the binary is position independent")

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&Binary::name),
        static_cast<setter_t<const std::string&>>(&Binary::name),
        "Binary's name")

    .def_property_readonly("header",
        &Binary::get_header,
        "Binary's header")

    .def_property_readonly("entrypoint",
        &Binary::entrypoint,
        "Binary's entrypoint")

    .def_property_readonly("sections",
        static_cast<it_t<it_sections>>(&Binary::get_sections),
        "Return a list in **read only** of binary's abstract " RST_CLASS_REF(lief.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_functions",
        &Binary::get_exported_functions,
        "Return binary's exported functions (name)")

    .def_property_readonly("imported_functions",
        &Binary::get_imported_functions,
        "Return binary's imported functions (name)")

    .def_property_readonly("libraries",
        &Binary::get_imported_libraries,
        "Return binary's imported libraries (name)")

    .def_property_readonly("symbols",
        static_cast<it_t<it_symbols>>(&Binary::get_symbols),
        "Return a list in **read only** of binary's abstract " RST_CLASS_REF(lief.Symbol) "",
        py::return_value_policy::reference_internal)

    .def("get_function_address",
        &Binary::get_function_address,
        "Return the address of the given function name",
        "function_name"_a)

    .def("patch_address",
        static_cast<void (Binary::*) (uint64_t, const std::vector<uint8_t>&)>(&Binary::patch_address),
        "Patch the address with the given value",
        py::arg("address"), py::arg("patch_value"))

    .def("patch_address",
        static_cast<void (Binary::*) (uint64_t, uint64_t, size_t)>(&Binary::patch_address),
        "Patch the address with the given value",
        py::arg("address"), py::arg("patch_value"), py::arg_v("size", 8))


   .def("get_content_from_virtual_address",
        &Binary::get_content_from_virtual_address,
       "Return the content located at virtual address",
       "virtual_address"_a, "size"_a)


    .def("__str__",
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          std::string str = stream.str();
          return str;
        });

}



