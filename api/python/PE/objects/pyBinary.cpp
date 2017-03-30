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
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/Abstract/Binary.hpp"

#include "pyPE.hpp"


template<class T, class P>
using no_const_func = T (Binary::*)(P);

template<class T>
using no_const_getter = T (Binary::*)(void);

void init_PE_Binary_class(py::module& m) {
  py::class_<Binary, LIEF::Binary>(m, "Binary")
    .def(py::init<const std::string &, PE_TYPE>())

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&Binary::get_sections),
        "Return binary's " RST_CLASS_REF(lief.PE.Section) " sections",
        py::return_value_policy::reference)

    .def_property_readonly("dos_header",
        static_cast<DosHeader& (Binary::*)(void)>(&Binary::dos_header),
        "Return " RST_CLASS_REF(lief.PE.DosHeader) "",
        py::return_value_policy::reference)

    .def_property_readonly("header",
        static_cast<Header& (Binary::*)(void)>(&Binary::header),
        "Return " RST_CLASS_REF(lief.PE.Header) "",
        py::return_value_policy::reference)

    .def_property_readonly("optional_header",
        static_cast<OptionalHeader& (Binary::*)(void)>(&Binary::optional_header),
        "Return " RST_CLASS_REF(lief.PE.OptionalHeader) "",
        py::return_value_policy::reference)

    .def_property_readonly("virtual_size",
        &Binary::get_virtual_size)

    .def_property_readonly("sizeof_headers",
        &Binary::get_sizeof_headers)

    .def("rva_to_offset",
        &Binary::rva_to_offset,
        "Convert a relative virtual address to an offset")


    .def("va_to_offset",
        &Binary::va_to_offset,
        "Convert a **absolute** virtual address to an offset")


    .def("section_from_offset",
        static_cast<Section& (Binary::*)(uint64_t)>(&Binary::section_from_offset),
        "Return the " RST_CLASS_REF(lief.PE.Section) " which contains the offset",
        py::return_value_policy::reference)


    .def("section_from_virtual_address",
        static_cast<Section& (Binary::*)(uint64_t)>(&Binary::section_from_virtual_address),
        "Return the " RST_CLASS_REF(lief.PE.Section) " which contains the (relative) virtual address",
        py::return_value_policy::reference)


    .def_property("tls",
      static_cast<TLS& (Binary::*)(void)>(&Binary::tls),
      static_cast<void (Binary::*)(const TLS&)>(&Binary::tls),
      py::return_value_policy::reference)


    .def_property_readonly("has_debug", &Binary::has_debug,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Debug) " object")

    .def_property_readonly("has_tls", &Binary::has_tls,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.TLS) " object")

    .def_property_readonly("has_imports", &Binary::has_imports,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Import) " object")

    .def_property_readonly("has_exports", &Binary::has_exports,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Export) " object")

    .def_property_readonly("has_resources", &Binary::has_resources,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Resources) " object")

    .def_property_readonly("has_exceptions", &Binary::has_exceptions,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Execptions) " object")

    .def_property_readonly("has_relocations", &Binary::has_relocations,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Relocation) "")

    .def_property_readonly("has_configurations", &Binary::has_configuration,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Configuration) "")

    .def_property_readonly("has_signature", &Binary::has_signature,
        "Check if the current binary has a " RST_CLASS_REF(lief.PE.Signature) "")

    .def("predict_function_rva", &Binary::predict_function_rva,
        "Try to predict the RVA of the function `function` in the import library `library`",
        py::arg("library"), py::arg("function"))


    .def_property_readonly("signature",
        static_cast<const Signature& (Binary::*)(void) const>(&Binary::signature),
        py::return_value_policy::reference)


    .def_property_readonly("debug",
        static_cast<Debug& (Binary::*)(void)>(&Binary::get_debug),
        py::return_value_policy::reference)

    .def("get_export",
        static_cast<Export& (Binary::*)(void)>(&Binary::get_export),
        "Return a " RST_CLASS_REF(lief.PE.Export) " object",
        py::return_value_policy::reference)

    .def_property_readonly("symbols",
        static_cast<std::vector<Symbol>& (Binary::*)(void)>(&Binary::symbols),
        "Return binary's " RST_CLASS_REF(lief.PE.Symbol) "",
        py::return_value_policy::reference)

    .def("get_section",
        static_cast<no_const_func<Section&, const std::string&>>(&Binary::get_section),
        py::return_value_policy::reference)

    .def("add_section",
        &Binary::add_section,
        py::return_value_policy::reference)

    //.def("delete_section", (void (Binary::*)(const std::string&)) &Binary::delete_section)
    //.def("get_import_section",
    //    static_cast<no_const_getter<Section&>>(&Binary::get_import_section),
    //    py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<no_const_getter<it_relocations>>(&Binary::relocations),
        py::return_value_policy::reference)

    .def("add_relocation", &Binary::add_relocation)
    .def("remove_all_relocations", &Binary::remove_all_relocations)

    .def_property_readonly("data_directories",
        static_cast<no_const_getter<it_data_directories>>(&Binary::data_directories),
        py::return_value_policy::reference)

    .def("data_directory",
        static_cast<DataDirectory& (Binary::*) (DATA_DIRECTORY)>(&Binary::data_directory),
        py::return_value_policy::reference)

    .def_property_readonly("imports",
        static_cast<no_const_getter<it_imports>>(&Binary::imports),
        py::return_value_policy::reference)

    .def_property_readonly("resources_manager",
        static_cast<no_const_getter<ResourcesManager>>(&Binary::get_resources_manager))

    .def("add_import_function",
        &Binary::add_import_function,
        py::return_value_policy::reference)

    .def("add_library",
        &Binary::add_library,
        py::return_value_policy::reference)

    .def("remove_library",            &Binary::remove_library)
    .def("remove_all_libraries",      &Binary::remove_all_libraries)

    .def("write", &Binary::write)

    .def_property_readonly("entrypoint", &Binary::entrypoint)

    .def("__str__",
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          std::string str = stream.str();
          return str;
        });

}
