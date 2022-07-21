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
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/Abstract/Binary.hpp"

#include "pyPE.hpp"
#include "pyIterators.hpp"

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

  py::class_<Binary, LIEF::Binary> bin(m, "Binary",
      R"delim(
      Class which represents a PE binary which is the main interface
      to manage and modify a PE executable.

      This object can be instantiated through :func:`lief.parse` or :func:`lief.PE.parse` while
      the constructor of this object can be used to craft a binary from scratch (see: :ref:`02-pe-from-scratch`)
      )delim");

  init_ref_iterator<Binary::it_sections>(bin, "it_section");
  init_ref_iterator<Binary::it_data_directories>(bin, "it_data_directories");
  init_ref_iterator<Binary::it_relocations>(bin, "it_relocations");
  init_ref_iterator<Binary::it_imports>(bin, "it_imports");
  init_ref_iterator<Binary::it_delay_imports>(bin, "it_delay_imports");
  init_ref_iterator<Binary::it_symbols>(bin, "it_symbols");
  init_ref_iterator<Binary::it_const_signatures>(bin, "it_const_signatures");

  bin
    .def(py::init<const std::string&, PE_TYPE>(),
         "name"_a, "type"_a)

    .def_property_readonly("sections",
        static_cast<no_const_getter<Binary::it_sections>>(&Binary::sections),
        "Return binary's an iterator over the PE's " RST_CLASS_REF(lief.PE.Section) "",
        py::return_value_policy::reference)

    .def_property_readonly("dos_header",
        static_cast<DosHeader& (Binary::*)(void)>(&Binary::dos_header),
        "Return the " RST_CLASS_REF(lief.PE.DosHeader) "",
        py::return_value_policy::reference)

    .def_property_readonly("header",
        static_cast<Header& (Binary::*)(void)>(&Binary::header),
        "Return the " RST_CLASS_REF(lief.PE.Header) "",
        py::return_value_policy::reference)

    .def_property_readonly("optional_header",
        static_cast<OptionalHeader& (Binary::*)(void)>(&Binary::optional_header),
        "Return the " RST_CLASS_REF(lief.PE.OptionalHeader) "",
        py::return_value_policy::reference)

    .def_property_readonly("virtual_size",
        &Binary::virtual_size,
        R"delim(
        Return the binary's virtual size.

        This value should match :attr:`~lief.PE.OptionalHeader.sizeof_image`
        )delim")

    .def_property_readonly("sizeof_headers",
        &Binary::sizeof_headers,
        "Size of all the PE headers")

    .def("rva_to_offset",
        &Binary::rva_to_offset,
        "rva_address"_a,
        R"delim(
        Convert a relative virtual address to an offset

        The conversion is performed by looking for the section that encompasses the provided RVA.
        )delim")

    .def("va_to_offset",
        &Binary::va_to_offset,
        "va_address"_a,
        R"delim(
        Convert an **absolute** virtual address into an offset

        See: :meth:`~lief.PE.Binary.rva_to_offset`
        )delim")

    .def("section_from_offset",
        static_cast<Section* (Binary::*)(uint64_t)>(&Binary::section_from_offset),
        R"delim(
        Return the :class:`~lief.PE.Section` which encompasses the provided offset.
        It returns None if a section can't be found.
        )delim",
        "offset"_a,
        py::return_value_policy::reference)

    .def("section_from_rva",
        static_cast<Section* (Binary::*)(uint64_t)>(&Binary::section_from_rva),
        R"delim(
        Return the :class:`~lief.PE.Section` which encompasses the provided **relative** virtual address.
        If a section can't be found, it returns None.
        )delim",
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
        "``True`` if the current binary has imports (" RST_CLASS_REF(lief.PE.Import) ")")

    .def_property_readonly("has_exports", &Binary::has_exports,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Export) " object")

    .def_property_readonly("has_resources", &Binary::has_resources,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Resources) " object")

    .def_property_readonly("has_exceptions", &Binary::has_exceptions,
        "``True`` if the current binary uses ``Exceptions``")

    .def_property_readonly("has_relocations", &Binary::has_relocations,
        "``True`` if the current binary uses " RST_CLASS_REF(lief.PE.Relocation) "")

    .def_property_readonly("has_configuration", &Binary::has_configuration,
        "``True`` if the current binary has " RST_CLASS_REF(lief.PE.LoadConfiguration) "")

    .def_property_readonly("has_signatures", &Binary::has_signatures,
        "``True`` if the binary is signed with the PE authenticode (" RST_CLASS_REF(lief.PE.Signature) ")")

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
        static_cast<Binary::it_const_signatures (Binary::*)(void) const>(&Binary::signatures),
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
        static_cast<Signature::VERIFICATION_FLAGS(Binary::*)(Signature::VERIFICATION_CHECKS) const>(&Binary::verify_signature),
        R"delim(
        Verify the binary against the embedded signature(s) (if any)

        First off, it checks that the embedded signatures are correct (c.f. :meth:`lief.PE.Signature.check`)
        and then it checks that the authentihash matches :attr:`lief.PE.ContentInfo.digest`

        One can tweak the verification process with the :class:`lief.PE.Signature.VERIFICATION_CHECKS` flags

        .. seealso::

            :meth:`lief.PE.Signature.check`
        )delim",
        "checks"_a = Signature::VERIFICATION_CHECKS::DEFAULT)

    .def("verify_signature",
        static_cast<Signature::VERIFICATION_FLAGS(Binary::*)(const Signature&, Signature::VERIFICATION_CHECKS) const>(&Binary::verify_signature),
        R"delim(
        Verify the binary with the Signature object provided in the first parameter
        It can be used to verify a detached signature:

        .. code-block:: python

            detached = lief.PE.Signature.parse("sig.pkcs7")
            binary.verify_signature(detached)
        )delim",
        "signature"_a, "checks"_a = Signature::VERIFICATION_CHECKS::DEFAULT)

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
        static_cast<Binary::debug_entries_t& (Binary::*)(void)>(&Binary::debug),
        "Return the " RST_CLASS_REF(lief.PE.Debug) "",
        py::return_value_policy::reference)

    .def_property_readonly("load_configuration",
        static_cast<LoadConfiguration* (Binary::*)(void)>(&Binary::load_configuration),
        "Return the " RST_CLASS_REF(lief.PE.LoadConfiguration) " object or None if not present",
        py::return_value_policy::reference)

    .def("get_export",
        static_cast<Export& (Binary::*)(void)>(&Binary::get_export),
        "Return the " RST_CLASS_REF(lief.PE.Export) " object",
        py::return_value_policy::reference)

    .def_property_readonly("symbols",
        static_cast<std::vector<Symbol>& (Binary::*)(void)>(&Binary::symbols),
        "Return binary's " RST_CLASS_REF(lief.PE.Symbol) "",
        py::return_value_policy::reference)

    .def("get_section",
        static_cast<no_const_func<Section*, const std::string&>>(&Binary::get_section),
        "Return the " RST_CLASS_REF(lief.PE.Section) " object from the given name or None if not not found",
        "section_name"_a,
        py::return_value_policy::reference)

    .def("add_section",
        &Binary::add_section,
        "Add a " RST_CLASS_REF(lief.PE.Section) " to the binary.",
        "section"_a, py::arg("type") = PE_SECTION_TYPES::UNKNOWN,
        py::return_value_policy::reference)

    .def_property_readonly("relocations",
        static_cast<no_const_getter<Binary::it_relocations>>(&Binary::relocations),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.Relocation) "",
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
        static_cast<no_const_getter<Binary::it_data_directories>>(&Binary::data_directories),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.DataDirectory) "",
        py::return_value_policy::reference)

    .def("data_directory",
        static_cast<DataDirectory& (Binary::*) (DATA_DIRECTORY)>(&Binary::data_directory),
        "Return the " RST_CLASS_REF(lief.PE.DataDirectory) " object from the given " RST_CLASS_REF(lief.PE.DATA_DIRECTORY) " type",
        "type"_a,
        py::return_value_policy::reference)

    .def_property_readonly("imports",
        static_cast<no_const_getter<Binary::it_imports>>(&Binary::imports),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.Import) " libraries",
        py::return_value_policy::reference)

    .def("has_import",
        &Binary::has_import,
        "``True`` if the binary imports the given library name",
        "import_name"_a)

    .def("get_import",
        static_cast<no_const_func<Import*, const std::string&>>(&Binary::get_import),
        "Return the " RST_CLASS_REF(lief.PE.Import) " from the given name or None if not not found",
        "import_name"_a,
        py::return_value_policy::reference)

    .def_property_readonly("delay_imports",
        static_cast<no_const_getter<Binary::it_delay_imports>>(&Binary::delay_imports),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.DelayImport) " ")

    .def_property_readonly("has_delay_imports", &Binary::has_delay_imports,
        "``True`` if the current binary has delay imports (" RST_CLASS_REF(lief.PE.DelayImport) ")")

    .def("has_delay_import",
        &Binary::has_delay_import,
        "``True`` if the binary imports the given library name",
        "import_name"_a)

    .def("get_delay_import",
        static_cast<no_const_func<DelayImport*, const std::string&>>(&Binary::get_delay_import),
        "Return the " RST_CLASS_REF(lief.PE.DelayImport) " from the given name or None if not not found",
        "import_name"_a,
        py::return_value_policy::reference)

    .def_property_readonly("resources_manager",
        [] (Binary& self) {
          return error_or(&Binary::resources_manager, self);
        },
        "Return the " RST_CLASS_REF(lief.PE.ResourcesManager) " to manage resources")

    .def_property_readonly("resources",
        static_cast<no_const_getter<ResourceNode*>>(&Binary::resources),
        "Return the " RST_CLASS_REF(lief.PE.ResourceNode) " tree or None if not not present",
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
        "**DEPRECATED**",
        "function_name"_a, "hook_address"_a)

    .def("hook_function",
        static_cast<void (Binary::*)(const std::string&, const std::string&, uint64_t)>(&Binary::hook_function),
        "**DEPRECATED**",
        "library_name"_a, "function_name"_a, "hook_address"_a)

    .def("remove_all_libraries",
        &Binary::remove_all_libraries,
        "Remove all imported libraries")

    .def("write",
        static_cast<void (Binary::*)(const std::string&)>(&Binary::write),
        "Build the binary and write the result to the given ``output`` file",
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
