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
#include <algorithm>

#include "pyAbstract.hpp"
#include "LIEF/Abstract/Binary.hpp"

#define PY_ENUM(x) LIEF::to_string(x), x

namespace LIEF {

template<class T>
using getter_t = T (Binary::*)(void) const;

template<class T>
using setter_t = void (Binary::*)(T);

template<class T>
using it_t = T (Binary::*)(void);

template<class T, class P>
using no_const_func = T (Binary::*)(P);

template<>
void create<Binary>(py::module& m) {
  py::class_<Binary, Object> pybinary(m, "Binary");

  py::enum_<Binary::VA_TYPES>(pybinary, "VA_TYPES")
    .value(PY_ENUM(Binary::VA_TYPES::AUTO))
    .value(PY_ENUM(Binary::VA_TYPES::VA))
    .value(PY_ENUM(Binary::VA_TYPES::RVA));

    pybinary
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

    .def("remove_section",
        static_cast<void (Binary::*)(const std::string&, bool)>(&Binary::remove_section),
        "Remove the section with the given name",
        "name"_a, "clear"_a = false)

    .def_property_readonly("sections",
        static_cast<it_t<it_sections>>(&Binary::sections),
        "Return a list in **read only** of binary's abstract " RST_CLASS_REF(lief.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<it_t<it_relocations>>(&Binary::relocations),
        "Return an iterator over abstract " RST_CLASS_REF(lief.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_functions",
        &Binary::exported_functions,
        "Return binary's exported " RST_CLASS_REF(lief.Function) "")

    .def_property_readonly("imported_functions",
        &Binary::imported_functions,
        "Return binary's imported " RST_CLASS_REF(lief.Function) " (name)")

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
        py::return_value_policy::reference_internal)

    .def("get_function_address",
        &Binary::get_function_address,
        "Return the address of the given function name",
        "function_name"_a)

    .def("patch_address",
        static_cast<void (Binary::*) (uint64_t, const std::vector<uint8_t>&, Binary::VA_TYPES)>(&Binary::patch_address),
        "Patch the address with the given value",
        "Virtual address is specified in the first argument and the content in the second (as a list of bytes).\n"
        "If the underlying binary is a PE, one can specify if the virtual address is a " RST_ATTR_REF(lief.Binary.VA_TYPES.RVA) ""
        " or a " RST_ATTR_REF(lief.Binary.VA_TYPES.VA) ". By default it is set to " RST_ATTR_REF(lief.Binary.VA_TYPES.AUTO) "",
        "address"_a, "patch_value"_a, "va_type"_a = Binary::VA_TYPES::AUTO)

    .def("patch_address",
        static_cast<void (Binary::*) (uint64_t, uint64_t, size_t, Binary::VA_TYPES)>(&Binary::patch_address),
        "Patch the address with the given value",
        "Virtual address is specified in the first argument, integer in the second and sizeof the integer in third one.\n"
        "If the underlying binary is a PE, one can specify if the virtual address is a " RST_ATTR_REF(lief.Binary.VA_TYPES.RVA) ""
        " or a " RST_ATTR_REF(lief.Binary.VA_TYPES.VA) ". By default it is set to " RST_ATTR_REF(lief.Binary.VA_TYPES.AUTO) "",
        "address"_a, "patch_value"_a, "size"_a = 8, "va_type"_a = Binary::VA_TYPES::AUTO)


   .def("get_content_from_virtual_address",
        &Binary::get_content_from_virtual_address,
        "Return the content located at virtual address.\n\n"
        "Virtual address is specified in the first argument and size to read (in bytes) in the second.\n"
        "If the underlying binary is a PE, one can specify if the virtual address is a " RST_ATTR_REF(lief.Binary.VA_TYPES.RVA) ""
        " or a " RST_ATTR_REF(lief.Binary.VA_TYPES.VA) ". By default it is set to " RST_ATTR_REF(lief.Binary.VA_TYPES.AUTO) "",
        "virtual_address"_a, "size"_a, "va_type"_a = Binary::VA_TYPES::AUTO)

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

    .def_property_readonly("ctor_functions",
        &Binary::ctor_functions,
        "Constructor functions that are called prior any other functions")

    .def("xref",
        &Binary::xref,
        "Return all **virtual addresses** that *use* the ``address`` given in parameter",
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

}

