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
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/Debug.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/RichHeader.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"

#include "PE/pyPE.hpp"

#include "pyErr.hpp"
#include "pyIterator.hpp"
#include "nanobind/extra/memoryview.hpp"
#include "nanobind/utils.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::PE::py {

template<>
void create<Binary>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Binary, LIEF::Binary> bin(m, "Binary",
      R"delim(
      Class which represents a PE binary which is the main interface
      to manage and modify a PE executable.

      This object can be instantiated through :func:`lief.parse` or :func:`lief.PE.parse` while
      the constructor of this object can be used to craft a binary from scratch (see: :ref:`02-pe-from-scratch`)
      )delim"_doc);

  init_ref_iterator<Binary::it_sections>(bin, "it_section");
  init_ref_iterator<Binary::it_data_directories>(bin, "it_data_directories");
  init_ref_iterator<Binary::it_relocations>(bin, "it_relocations");
  init_ref_iterator<Binary::it_imports>(bin, "it_imports");
  init_ref_iterator<Binary::it_delay_imports>(bin, "it_delay_imports");
  init_ref_iterator<Binary::it_symbols>(bin, "it_symbols");
  init_ref_iterator<Binary::it_const_signatures>(bin, "it_const_signatures");
  init_ref_iterator<Binary::it_debug_entries>(bin, "it_debug");

  bin
    .def(nb::init<PE_TYPE>(),
         "type"_a)

    .def_prop_ro("sections",
        nb::overload_cast<>(&Binary::sections),
        "Return binary's an iterator over the PE's " RST_CLASS_REF(lief.PE.Section) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("dos_header",
        nb::overload_cast<>(&Binary::dos_header, nb::const_),
        "Return the " RST_CLASS_REF(lief.PE.DosHeader) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("header",
        nb::overload_cast<>(&Binary::header, nb::const_),
        "Return the " RST_CLASS_REF(lief.PE.Header) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("optional_header",
        nb::overload_cast<>(&Binary::optional_header, nb::const_),
        R"doc(
        Header that follows the :attr:`~.header`. It is named optional from the
        COFF specifications but it is mandatory in a PE file.
        )doc"_doc,
        nb::rv_policy::reference_internal)

    .def("compute_checksum",
        &Binary::compute_checksum,
        R"delim(
        Re-compute the value of :attr:`~lief.PE.OptionalHeader.checksum`.
        If both values do not match, it could mean that the binary has been modified
        after the compilation.

        This value is computed by LIEF for the current binary object.
        )delim"_doc)

    .def_prop_ro("virtual_size",
        &Binary::virtual_size,
        R"delim(
        Return the binary's virtual size.

        This value should match :attr:`~lief.PE.OptionalHeader.sizeof_image`
        )delim"_doc)

    .def_prop_ro("sizeof_headers",
        &Binary::sizeof_headers,
        "Size of all the PE headers"_doc)

    .def("rva_to_offset",
        &Binary::rva_to_offset,
        "rva_address"_a,
        R"delim(
        Convert a relative virtual address to an offset

        The conversion is performed by looking for the section that encompasses the provided RVA.
        )delim"_doc)

    .def("va_to_offset",
        &Binary::va_to_offset,
        "va_address"_a,
        R"delim(
        Convert an **absolute** virtual address into an offset

        See: :meth:`~lief.PE.Binary.rva_to_offset`
        )delim"_doc)

    .def("section_from_offset",
        nb::overload_cast<uint64_t>(&Binary::section_from_offset),
        R"delim(
        Return the :class:`~lief.PE.Section` which encompasses the provided offset.
        It returns None if a section can't be found.
        )delim"_doc,
        "offset"_a,
        nb::rv_policy::reference_internal)

    .def("section_from_rva",
        nb::overload_cast<uint64_t>(&Binary::section_from_rva),
        R"delim(
        Return the :class:`~lief.PE.Section` which encompasses the provided **relative** virtual address.
        If a section can't be found, it returns None.
        )delim"_doc,
        "rva"_a,
        nb::rv_policy::reference_internal)

    .def_prop_rw("tls",
      nb::overload_cast<>(&Binary::tls),
      nb::overload_cast<const TLS&>(&Binary::tls),
      "" RST_CLASS_REF(lief.PE.TLS) " object (if present)"_doc,
      nb::rv_policy::reference_internal)

    .def_prop_rw("rich_header",
      nb::overload_cast<>(&Binary::rich_header),
      nb::overload_cast<const RichHeader&>(&Binary::rich_header),
      "" RST_CLASS_REF(lief.PE.RichHeader) " object (if present)"_doc,
      nb::rv_policy::reference_internal)

    .def_prop_ro("has_rich_header", &Binary::has_rich_header,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.RichHeader) " object"_doc)

    .def_prop_ro("has_debug", &Binary::has_debug,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Debug) " object"_doc)

    .def_prop_ro("has_tls", &Binary::has_tls,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.TLS) " object"_doc)

    .def_prop_ro("has_imports", &Binary::has_imports,
        "``True`` if the current binary has imports (" RST_CLASS_REF(lief.PE.Import) ")"_doc)

    .def_prop_ro("has_exports", &Binary::has_exports,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Export) " object"_doc)

    .def_prop_ro("has_resources", &Binary::has_resources,
        "``True`` if the current binary has a " RST_CLASS_REF(lief.PE.Resources) " object"_doc)

    .def_prop_ro("has_exceptions", &Binary::has_exceptions,
        "``True`` if the current binary uses ``Exceptions``"_doc)

    .def_prop_ro("has_relocations", &Binary::has_relocations,
        "``True`` if the current binary uses " RST_CLASS_REF(lief.PE.Relocation) ""_doc)

    .def_prop_ro("has_configuration", &Binary::has_configuration,
        "``True`` if the current binary has " RST_CLASS_REF(lief.PE.LoadConfiguration) ""_doc)

    .def_prop_ro("has_signatures", &Binary::has_signatures,
        "``True`` if the binary is signed with the PE authenticode (" RST_CLASS_REF(lief.PE.Signature) ")"_doc)

    .def_prop_ro("is_reproducible_build", &Binary::is_reproducible_build,
        "``True`` if the binary was compiled with a reproducible build directive (" RST_CLASS_REF(lief.PE.Debug) ")"_doc)

    .def_prop_ro("functions",
        &Binary::functions,
        "**All** " RST_CLASS_REF(lief.Function) " found in the binary"_doc)

    .def_prop_ro("exception_functions",
        &Binary::exception_functions,
        "" RST_CLASS_REF(lief.Function) " found in the Exception directory"_doc)

    .def("predict_function_rva",
        nb::overload_cast<const std::string&, const std::string&>(&Binary::predict_function_rva),
        "Try to predict the RVA of the given function name in the given import library name"_doc,
        "library"_a, "function"_a)

    .def_prop_ro("signatures",
        nb::overload_cast<>(&Binary::signatures, nb::const_),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.Signature) " objects"_doc,
        nb::keep_alive<0, 1>())

    .def("authentihash",
        [] (const Binary& bin, ALGORITHMS algo) {
          return nb::to_bytes(bin.authentihash(algo));
        },
        "Compute the authentihash according to the " RST_CLASS_REF(lief.PE.ALGORITHMS) " "
        "given in the first parameter"_doc,
        "algorithm"_a)

    .def("verify_signature",
        nb::overload_cast<Signature::VERIFICATION_CHECKS>(&Binary::verify_signature, nb::const_),
        R"delim(
        Verify the binary against the embedded signature(s) (if any)

        First off, it checks that the embedded signatures are correct (c.f. :meth:`lief.PE.Signature.check`)
        and then it checks that the authentihash matches :attr:`lief.PE.ContentInfo.digest`

        One can tweak the verification process with the :class:`lief.PE.Signature.VERIFICATION_CHECKS` flags

        .. seealso::

            :meth:`lief.PE.Signature.check`
        )delim"_doc,
        "checks"_a = Signature::VERIFICATION_CHECKS::DEFAULT)

    .def("verify_signature",
        nb::overload_cast<const Signature&, Signature::VERIFICATION_CHECKS>(&Binary::verify_signature, nb::const_),
        R"delim(
        Verify the binary with the Signature object provided in the first parameter
        It can be used to verify a detached signature:

        .. code-block:: python

            detached = lief.PE.Signature.parse("sig.pkcs7")
            binary.verify_signature(detached)
        )delim"_doc,
        "signature"_a, "checks"_a = Signature::VERIFICATION_CHECKS::DEFAULT)

    .def_prop_ro("authentihash_md5",
        [] (const Binary& bin) {
          return nb::to_bytes(bin.authentihash(ALGORITHMS::MD5));
        },
        "Authentihash **MD5** value"_doc)

    .def_prop_ro("authentihash_sha1",
        [] (const Binary& bin) {
          return nb::to_bytes(bin.authentihash(ALGORITHMS::SHA_1));
        },
        "Authentihash **SHA1** value"_doc)

    .def_prop_ro("authentihash_sha256",
        [] (const Binary& bin) {
          return nb::to_bytes(bin.authentihash(ALGORITHMS::SHA_256));
        },
        "Authentihash **SHA-256** value"_doc)

    .def_prop_ro("authentihash_sha512",
        [] (const Binary& bin) {
          return nb::to_bytes(bin.authentihash(ALGORITHMS::SHA_512));
        },
        "Authentihash **SHA-512** value"_doc)

    .def_prop_ro("debug",
        nb::overload_cast<>(&Binary::debug),
        "Return the " RST_CLASS_REF(lief.PE.Debug) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("codeview_pdb",
        nb::overload_cast<>(&Binary::codeview_pdb, nb::const_),
        "Return the :class:`~.CodeViewPDB` if present"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("load_configuration",
        nb::overload_cast<>(&Binary::load_configuration),
        "Return the " RST_CLASS_REF(lief.PE.LoadConfiguration) " object or None if not present"_doc,
        nb::rv_policy::reference_internal)

    .def("get_export",
        nb::overload_cast<>(&Binary::get_export),
        "Return the " RST_CLASS_REF(lief.PE.Export) " object"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("symbols",
        nb::overload_cast<>(&Binary::symbols),
        "Return binary's " RST_CLASS_REF(lief.PE.Symbol) ""_doc,
        nb::rv_policy::reference_internal)

    .def("get_section",
        nb::overload_cast<const std::string&>(&Binary::get_section),
        "Return the " RST_CLASS_REF(lief.PE.Section) " object from the given name or None if not not found"_doc,
        "section_name"_a,
        nb::rv_policy::reference_internal)

    .def("add_section",
        &Binary::add_section,
        "Add a " RST_CLASS_REF(lief.PE.Section) " to the binary."_doc,
        "section"_a, nb::arg("type") = PE_SECTION_TYPES::UNKNOWN,
        nb::rv_policy::reference_internal)

    .def_prop_ro("relocations",
        nb::overload_cast<>(&Binary::relocations),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def("add_relocation",
        &Binary::add_relocation,
        "Add a " RST_CLASS_REF(lief.PE.Relocation) " to the binary"_doc,
        "relocation"_a)

    .def("remove_all_relocations", &Binary::remove_all_relocations)

    .def("remove",
        nb::overload_cast<const Section&, bool>(&Binary::remove),
        "Remove the " RST_CLASS_REF(lief.PE.Section) " given in first parameter"_doc,
        "section"_a, "clear"_a = false)

    .def_prop_ro("data_directories",
        nb::overload_cast<>(&Binary::data_directories),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.DataDirectory) ""_doc,
        nb::keep_alive<0, 1>())

    .def("data_directory",
        nb::overload_cast<DataDirectory::TYPES>(&Binary::data_directory),
        "Return the " RST_CLASS_REF(lief.PE.DataDirectory) " object from the given " RST_CLASS_REF(lief.PE.DataDirectory.TYPES) " type"_doc,
        "type"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("imports",
        nb::overload_cast<>(&Binary::imports),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.Import) " libraries"_doc,
        nb::keep_alive<0, 1>())

    .def("has_import",
        &Binary::has_import,
        "``True`` if the binary imports the given library name"_doc,
        "import_name"_a)

    .def("get_import",
        nb::overload_cast<const std::string&>(&Binary::get_import),
        "Return the " RST_CLASS_REF(lief.PE.Import) " from the given name or None if not not found"_doc,
        "import_name"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("delay_imports",
        nb::overload_cast<>(&Binary::delay_imports),
        "Return an iterator over the " RST_CLASS_REF(lief.PE.DelayImport) " "_doc)

    .def_prop_ro("has_delay_imports", &Binary::has_delay_imports,
        "``True`` if the current binary has delay imports (" RST_CLASS_REF(lief.PE.DelayImport) ")"_doc)

    .def("has_delay_import",
        &Binary::has_delay_import,
        "``True`` if the binary imports the given library name"_doc,
        "import_name"_a)

    .def("get_delay_import",
        nb::overload_cast<const std::string&>(&Binary::get_delay_import),
        "Return the " RST_CLASS_REF(lief.PE.DelayImport) " from the given name or None if not not found"_doc,
        "import_name"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("resources_manager",
        [] (Binary& self) {
          return error_or(&Binary::resources_manager, self);
        },
        "Return the " RST_CLASS_REF(lief.PE.ResourcesManager) " to manage resources"_doc)

    .def_prop_ro("resources",
        nb::overload_cast<>(&Binary::resources),
        "Return the " RST_CLASS_REF(lief.PE.ResourceNode) " tree or None if not not present"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("overlay",
        [] (Binary& self) {
          const span<const uint8_t> content = self.overlay();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        "Return the overlay content as a ``list`` of bytes"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("overlay_offset", &Binary::overlay_offset,
                 "Return the original overlay offset")

    .def_prop_rw("dos_stub",
        [] (Binary& self) {
          const span<const uint8_t> content = self.dos_stub();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<std::vector<uint8_t>>(&Binary::dos_stub),
        "DOS stub content as a ``list`` of bytes"_doc)

    .def("add_import_function",
        &Binary::add_import_function,
        "Add a function to the given " RST_CLASS_REF(lief.PE.Import) " name"_doc,
        "import_name"_a, "function_name"_a,
        nb::rv_policy::reference_internal)

    .def("add_library",
        &Binary::add_library,
        "Add an " RST_CLASS_REF(lief.PE.Import) " by name"_doc,
        "import_name"_a,
        nb::rv_policy::reference_internal)

    .def("remove_library",
        &Binary::remove_library,
        "Remove the " RST_CLASS_REF(lief.PE.Import) " from the given name"_doc,
        "import_name"_a)

    .def("remove_all_libraries",
        &Binary::remove_all_libraries,
        "Remove all imported libraries"_doc)

    .def("write",
        nb::overload_cast<const std::string&>(&Binary::write),
        "Build the binary and write the result to the given ``output`` file"_doc,
        "output_path"_a)

    LIEF_DEFAULT_STR(Binary);

}

}
