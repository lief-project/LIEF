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

template<class T, class P>
using no_const_func = T (Binary::*)(P);

void init_LIEF_Binary_class(py::module& m) {
  py::class_<Binary, Object>(m, "Binary")

    .def_property_readonly("format",
        &Binary::format,
        "File format " RST_CLASS_REF(lief.EXE_FORMATS) " of the underlying binary.")

    .def_property_readonly("is_pie",
        &Binary::is_pie,
        "Check if the binary is position independent")

    .def_property_readonly("has_nx",
        &Binary::has_nx,
        "Check if the binary uses ``NX`` protection")

    .def_property("name",
        static_cast<getter_t<const std::string&>>(&Binary::name),
        static_cast<setter_t<const std::string&>>(&Binary::name),
        "Binary's name")

    .def_property_readonly("header",
        &Binary::header,
        "Binary's header")

    .def_property_readonly("entrypoint",
        &Binary::entrypoint,
        "Binary's entrypoint")

    .def_property_readonly("sections",
        static_cast<it_t<it_sections>>(&Binary::sections),
        "Return a list in **read only** of binary's abstract " RST_CLASS_REF(lief.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<it_t<it_relocations>>(&Binary::relocations),
        "Return an iterator over abstract " RST_CLASS_REF(lief.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_functions",
        [] (const Binary& binary) {
          const std::vector<std::string>& exported_functions = binary.exported_functions();
          std::vector<py::object> exported_functions_encoded;
          exported_functions_encoded.reserve(exported_functions.size());

          std::transform(
              std::begin(exported_functions),
              std::end(exported_functions),
              std::back_inserter(exported_functions_encoded),
              &safe_string_converter);
          return exported_functions_encoded;

        },
        "Return binary's exported functions (name)")

    .def_property_readonly("imported_functions",
        [] (const Binary& binary) {
          const std::vector<std::string>& imported_functions = binary.imported_functions();
          std::vector<py::object> imported_functions_encoded;
          imported_functions_encoded.reserve(imported_functions.size());

          std::transform(
              std::begin(imported_functions),
              std::end(imported_functions),
              std::back_inserter(imported_functions_encoded),
              &safe_string_converter);
          return imported_functions_encoded;
        },
        "Return binary's imported functions (name)")

    .def_property_readonly("libraries",
        [] (const Binary& binary) {
          const std::vector<std::string>& imported_libraries = binary.imported_libraries();
          std::vector<py::object> imported_libraries_encoded;
          imported_libraries_encoded.reserve(imported_libraries.size());

          std::transform(
              std::begin(imported_libraries),
              std::end(imported_libraries),
              std::back_inserter(imported_libraries_encoded),
              &safe_string_converter);
          return imported_libraries_encoded;
        },
        "Return binary's imported libraries (name)")

    .def_property_readonly("symbols",
        static_cast<it_t<it_symbols>>(&Binary::symbols),
        "Return a list in **read only** of binary's abstract " RST_CLASS_REF(lief.Symbol) "",
        py::return_value_policy::reference_internal)

    .def("has_symbol",
        &Binary::has_symbol,
        "Check if a " RST_CLASS_REF(lief.Symbol) " with the given name exists",
        "symbol_name"_a)

    .def("get_symbol",
        static_cast<no_const_func<Symbol&, const std::string&>>(&Binary::get_symbol),
        "Return the " RST_CLASS_REF(lief.Symbol) " with the given ``name``",
        "symbol_name"_a,
        py::return_value_policy::reference)

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

    .def_property_readonly("abstract",
        [m] (py::object& self) {
          self.attr("__class__") = m.attr("Binary");
          return self;
        },
        "Return the " RST_CLASS_REF(lief.Binary) " object\n\n"
        ".. warning::\n\n"
        "\tGetting this property modifies the ``__class__`` attribute so that "
        "the current binary looks like a " RST_CLASS_REF(lief.Binary) ".\n\n"
        "\tUse the " RST_ATTR_REF(lief.Binary.concrete) " to get back to the original binary.",
        py::return_value_policy::reference)


    .def_property_readonly("concrete",
        [m] (py::object& self) {
          self.attr("__class__") = py::cast(self.cast<Binary*>()).attr("__class__");
          return self;
        },
        "Return either " RST_CLASS_REF_FULL(lief.ELF.Binary) ", " RST_CLASS_REF_FULL(lief.PE.Binary) ", " RST_CLASS_REF_FULL(lief.MachO.Binary) " object\n\n"
        "",
        py::return_value_policy::reference)

    .def("xref",
        &Binary::xref,
        "Return all **virtual address** that *use* the ``address`` given in parameter"
       "virtual_address"_a)

    .def("__str__",
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          std::string str = stream.str();
          return str;
        });

}



