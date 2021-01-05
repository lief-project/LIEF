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

namespace LIEF {
namespace PE {

template<class T, class P>
using no_const_func = T (Binary::*)(P);

template<class T>
using no_const_getter = T (Binary::*)(void);

template<class T>
using getter_t = T (Binary::*)(void) const;

template<class T>
using setter_t = void (Binary::*)(T);


template<>
void create<Binary>(py::module& m) {

  py::class_<Binary, LIEF::Binary>(m, "Binary")
    .def(py::init<const std::string &, PE_TYPE>())

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&Binary::sections),
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
        &Binary::virtual_size,
        "Binary size when mapped in memory.\n\n"
        "This value should matches :attr:`~lief.PE.OptionalHeader.sizeof_image`")

    .def_property_readonly("sizeof_headers",
        &Binary::sizeof_headers,
        "Size of all PE headers")

    .def("rva_to_offset",
        &Binary::rva_to_offset,
        "rva_address"_a,
        "Convert a relative virtual address to an offset")

    .def("va_to_offset",
        &Binary::va_to_offset,
        "va_address"_a,
        "Convert a **absolute** virtual address to an offset")

    .def("section_from_offset",
        static_cast<Section& (Binary::*)(uint64_t)>(&Binary::section_from_offset),
        "Return the " RST_CLASS_REF(lief.PE.Section) " which contains the offset",
        "offset"_a,
        py::return_value_policy::reference)

    .def("section_from_rva",
        static_cast<Section& (Binary::*)(uint64_t)>(&Binary::section_from_rva),
        "Return the " RST_CLASS_REF(lief.PE.Section) " which contains the **relative** virtual address",
        "rva"_a,
        py::return_value_policy::reference)

    .def_property("tls",
      static_cast<TLS& (Binary::*)(void)>(&Binary::tls),
      static_cast<void (Binary::*)(const TLS&)>(&Binary::tls),
      "" RST_CLASS_REF(lief.PE.TLS) " object (if present)",
      py::return_value_policy::reference)

    .def_property("rich_header",
      static_cast<RichHeader& (Binary::*)(void)>(&Binary::rich_header),
      static_cast<void (Binary::*)(const RichHeader&)>(&Binary::rich_header),
      "" RST_CLASS_REF(lief.PE.RichHeader) " object (if present)",
      py::return_value_policy::reference)

    .def_property_readonly("has_rich_header", &Binary::has_rich_header,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.RichHeader) " object")

    .def_property_readonly("has_debug", &Binary::has_debug,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Debug) " object")

    .def_property_readonly("has_tls", &Binary::has_tls,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.TLS) " object")

    .def_property_readonly("has_imports", &Binary::has_imports,
        "``True`` if the current binary import libraries (" RST_CLASS_REF(lief.PE.Import) ")")

    .def_property_readonly("has_exports", &Binary::has_exports,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Export) " object")

    .def_property_readonly("has_resources", &Binary::has_resources,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Resources) " object")

    .def_property_readonly("has_exceptions", &Binary::has_exceptions,
        "``True`` if the current binary has ``Exceptions``")

    .def_property_readonly("has_relocations", &Binary::has_relocations,
        "``True`` if the current binary use " RST_CLASS_REF(lief.PE.Relocation) "")

    .def_property_readonly("has_configuration", &Binary::has_configuration,
        "``True`` if the current binary has " RST_CLASS_REF(lief.PE.LoadConfiguration) "")

    .def_property_readonly("has_signatures", &Binary::has_signatures,
        "``True`` if the binary has signatures (" RST_CLASS_REF(lief.PE.Signature) ")")

    .def_property_readonly("is_reproducible_build", &Binary::is_reproducible_build,
        "``True`` if the binary was compiled with a reproducible build directive (" RST_CLASS_REF(lief.PE.Debug) ")")

    .def_property_readonly("functions",
        &Binary::functions,
        "**All** " RST_CLASS_REF(lief.Function) " found in the binary")

    .def_property_readonly("exception_functions",
        &Binary::exception_functions,
        "" RST_CLASS_REF(lief.Function) " found in the Exception directory")

    .def("predict_function_rva",
        static_cast<uint32_t(Binary::*)(const std::string&, const std::string&)>(&Binary::predict_function_rva),
        "Try to predict the RVA of the given function name in the given import library name",
        "library"_a, "function"_a)

    .def_property_readonly("signatures",
        static_cast<it_const_signatures (Binary::*)(void) const>(&Binary::signatures),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.Signature) " objects",
        py::return_value_policy::reference)

    .def("authentihash",
        [] (const Binary& bin, ALGORITHMS algo) {
          const std::vector<uint8_t>& data = bin.authentihash(algo);
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Compute the authentihash according to the " RST_CLASS_REF(lief.PE.ALGORITHMS) " "
        "given in the first parameter",
        "algorithm"_a)

    .def("verify_signature",
        static_cast<Signature::VERIFICATION_FLAGS(Binary::*)() const>(&Binary::verify_signature),
        R"delim(
        Verify the binary against the embedded signature(s) (if any)
        Firstly, it checks that the embedded signatures are correct (c.f. :meth:`lief.PE.Signature.check`)
        and then it checks that the authentihash matches :attr:`lief.PE.ContentInfo.digest`
        )delim")

    .def("verify_signature",
        static_cast<Signature::VERIFICATION_FLAGS(Binary::*)(const Signature&) const>(&Binary::verify_signature),
        R"delim(
        Verify the binary with the Signature object provided in the first parameter
        It can be used to verify a detached signature:

        .. code-block:: python

            detached = lief.PE.Signature.parse("sig.pkcs7")
            binary.verify_signature(detached)
        )delim",
        "signature"_a)

    .def_property_readonly("authentihash_md5",
        [] (const Binary& bin) {
          const std::vector<uint8_t>& data = bin.authentihash(ALGORITHMS::MD5);
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Authentihash **MD5** value")

    .def_property_readonly("authentihash_sha1",
        [] (const Binary& bin) {
          const std::vector<uint8_t>& data = bin.authentihash(ALGORITHMS::SHA_1);
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Authentihash **SHA1** value")

    .def_property_readonly("authentihash_sha256",
        [] (const Binary& bin) {
          const std::vector<uint8_t>& data = bin.authentihash(ALGORITHMS::SHA_256);
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Authentihash **SHA-256** value")

    .def_property_readonly("authentihash_sha512",
        [] (const Binary& bin) {
          const std::vector<uint8_t>& data = bin.authentihash(ALGORITHMS::SHA_512);
          return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        },
        "Authentihash **SHA-512** value")

    .def_property_readonly("debug",
        static_cast<debug_entries_t& (Binary::*)(void)>(&Binary::debug),
        "Return the " RST_CLASS_REF(lief.PE.Debug) "",
        py::return_value_policy::reference)

    .def_property_readonly("load_configuration",
        static_cast<LoadConfiguration& (Binary::*)(void)>(&Binary::load_configuration),
        "Return the " RST_CLASS_REF(lief.PE.LoadConfiguration) " object",
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
        "Return the " RST_CLASS_REF(lief.PE.Section) " object from the given name",
        "section_name"_a,
        py::return_value_policy::reference)

    .def("add_section",
        &Binary::add_section,
        "Add a " RST_CLASS_REF(lief.PE.Section) " to the binary.",
        "section"_a, py::arg("type") = PE_SECTION_TYPES::UNKNOWN,
        py::return_value_policy::reference)

    //.def("get_import_section",
    //    static_cast<no_const_getter<Section&>>(&Binary::get_import_section),
    //    py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<no_const_getter<it_relocations>>(&Binary::relocations),
        "Return an iterator on the " RST_CLASS_REF(lief.PE.Relocation) "",
        py::return_value_policy::reference)

    .def("add_relocation",
        &Binary::add_relocation,
        "Add a " RST_CLASS_REF(lief.PE.Relocation) " to the binary",
        "relocation"_a)

    .def("remove_all_relocations", &Binary::remove_all_relocations)

    .def("remove",
        static_cast<void(Binary::*)(const Section&, bool)>(&Binary::remove),
        "Remove the " RST_CLASS_REF(lief.PE.Section) " given in first parameter",
        "section"_a, "clear"_a = false)

    .def_property_readonly("data_directories",
        static_cast<no_const_getter<it_data_directories>>(&Binary::data_directories),
        "Return an iterator on the " RST_CLASS_REF(lief.PE.DataDirectory) "",
        py::return_value_policy::reference)

    .def("data_directory",
        static_cast<DataDirectory& (Binary::*) (DATA_DIRECTORY)>(&Binary::data_directory),
        "Return the " RST_CLASS_REF(lief.PE.DataDirectory) " object from the given " RST_CLASS_REF(lief.PE.DATA_DIRECTORY) " type",
        "type"_a,
        py::return_value_policy::reference)

    .def_property_readonly("imports",
        static_cast<no_const_getter<it_imports>>(&Binary::imports),
        "Return an iterator on the " RST_CLASS_REF(lief.PE.Import) " libraries",
        py::return_value_policy::reference)

    .def("has_import",
        &Binary::has_import,
        "``True`` if the binary import the given library name",
        "import_name"_a)

    .def("get_import",
        static_cast<no_const_func<Import&, const std::string&>>(&Binary::get_import),
        "Returns the " RST_CLASS_REF(lief.PE.Import) " from the given name",
        "import_name"_a,
        py::return_value_policy::reference)

    .def_property_readonly("resources_manager",
        static_cast<no_const_getter<ResourcesManager>>(&Binary::resources_manager),
        "Return the " RST_CLASS_REF(lief.PE.ResourcesManager) " to manage resources")

    .def_property_readonly("resources",
        static_cast<no_const_getter<ResourceNode&>>(&Binary::resources),
        "Return the " RST_CLASS_REF(lief.PE.ResourceNode) " tree",
        py::return_value_policy::reference)

    .def_property_readonly("overlay",
        static_cast<no_const_getter<std::vector<uint8_t>&>>(&Binary::overlay),
        "Return the overlay content as a ``list`` of bytes",
        py::return_value_policy::reference)

    .def_property("dos_stub",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&Binary::dos_stub),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&Binary::dos_stub),
        "DOS stub content as a ``list`` of bytes")

    .def("add_import_function",
        &Binary::add_import_function,
        "Add a function to the given " RST_CLASS_REF(lief.PE.Import) " name",
        "import_name"_a, "function_name"_a,
        py::return_value_policy::reference)

    .def("add_library",
        &Binary::add_library,
        "Add an " RST_CLASS_REF(lief.PE.Import) " by name",
        "import_name"_a,
        py::return_value_policy::reference)

    .def("remove_library",
        &Binary::remove_library,
        "Remove the " RST_CLASS_REF(lief.PE.Import) " from the given name",
        "import_name"_a)

    .def("hook_function",
        static_cast<void (Binary::*)(const std::string&, uint64_t)>(&Binary::hook_function),
        "Hook the given function name\n\n"
        ".. note:: \n\n"
        "\tWhen using this function, the :class:`~lief.PE.Builder` should be configured as follow:\n\n"
        "\t.. code-block:: python\n\n"
        "\t\t\n\n"
        "\t\tbuilder.build_imports(True).patch_imports(True)\n\n",
        "function_name"_a, "hook_address"_a)

    .def("hook_function",
        static_cast<void (Binary::*)(const std::string&, const std::string&, uint64_t)>(&Binary::hook_function),
        "Hook the function name from the given library name",
        "library_name"_a, "function_name"_a, "hook_address"_a)

    .def("remove_all_libraries",
        &Binary::remove_all_libraries,
        "Remove all imported libraries")

    .def("write",
        &Binary::write,
        "Build the binary and write the result to the given ``output``",
        "output_path"_a)

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
}
