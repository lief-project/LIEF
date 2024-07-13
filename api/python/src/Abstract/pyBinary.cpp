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
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "Abstract/init.hpp"
#include "pyLIEF.hpp"
#include "pyErr.hpp"
#include "pySafeString.hpp"
#include "nanobind/extra/memoryview.hpp"
#include "pyIterator.hpp"

#include "LIEF/logging.hpp"

#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/Abstract/Relocation.hpp"
#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/Abstract/Header.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

#include "LIEF/Abstract/DebugInfo.hpp"

namespace LIEF::py {
template<>
void create<Binary>(nb::module_& m) {
  nb::class_<Binary, Object> pybinary(m, "Binary",
      R"delim(
      File format abstract representation.

      This object represents the abstraction of an executable file format.
      It enables to access common features (like the :attr:`~lief.Binary.entrypoint`) regardless
      of the concrete format (e.g. :attr:`lief.ELF.Binary.entrypoint`)
      )delim"_doc);

# define ENTRY(X) .value(to_string(Binary::VA_TYPES::X), Binary::VA_TYPES::X)
  nb::enum_<Binary::VA_TYPES>(pybinary, "VA_TYPES")
    ENTRY(AUTO)
    ENTRY(VA)
    ENTRY(RVA)
  ;
# undef ENTRY

# define ENTRY(X) .value(to_string(Binary::FORMATS::X), Binary::FORMATS::X)
  nb::enum_<Binary::FORMATS>(pybinary, "FORMATS")
    ENTRY(UNKNOWN)
    ENTRY(ELF)
    ENTRY(PE)
    ENTRY(MACHO)
    ENTRY(OAT)
  ;
# undef ENTRY

  init_ref_iterator<Binary::it_sections>(pybinary, "it_sections");
  init_ref_iterator<Binary::it_symbols>(pybinary, "it_symbols");
  init_ref_iterator<Binary::it_relocations>(pybinary, "it_relocations");

  pybinary
    .def_prop_ro("debug_info",
        &Binary::debug_info,
        R"doc(
        Return debug info if present. It can be either a
        :class:`lief.dwarf.DebugInfo` or a :class:`lief.pdb.DebugInfo`

        For ELF and Mach-O binaries, it returns the given DebugInfo object **only**
        if the binary embeds the DWARF debug info in the binary itself.

        For PE file, this function tries to find the **external** PDB using
        the :attr:`lief::PE.CodeViewPDB.filename` output (if present). One can also
        use :func:`lief.pdb.load` to manually load a PDB.

        .. warning::

            This function requires LIEF's extended version otherwise it
            **always** return a nullptr
        )doc"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("format",
        &Binary::format,
        "File format (:class:`~.FORMATS`) of the underlying binary."_doc)

    .def_prop_ro("is_pie",
        &Binary::is_pie,
        "Check if the binary is position independent"_doc)

    .def_prop_ro("has_nx",
        &Binary::has_nx,
        "Check if the binary has ``NX`` protection (non executable stack)"_doc)

    .def_prop_ro("header",
        &Binary::header,
        "Binary's abstract header (" RST_CLASS_REF(lief.Header) ")"_doc)

    .def_prop_ro("entrypoint",
        &Binary::entrypoint,
        "Binary's entrypoint"_doc)

    .def("remove_section",
        nb::overload_cast<const std::string&, bool>(&Binary::remove_section),
        "Remove the section with the given name"_doc,
        "name"_a, "clear"_a = false)

    .def_prop_ro("sections",
        nb::overload_cast<>(&Binary::sections),
        "Return an iterator over the binary's abstract sections (" RST_CLASS_REF(lief.Section) ")"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("relocations",
        nb::overload_cast<>(&Binary::relocations),
        "Return an iterator over abstract " RST_CLASS_REF(lief.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("exported_functions",
        &Binary::exported_functions,
        "Return the binary's exported " RST_CLASS_REF(lief.Function) ""_doc)

    .def_prop_ro("imported_functions",
        &Binary::imported_functions,
        "Return the binary's imported " RST_CLASS_REF(lief.Function) " (name)"_doc)

    .def_prop_ro("libraries",
        [] (const Binary& binary) {
          const std::vector<std::string>& imported_libraries = binary.imported_libraries();
          std::vector<nb::object> imported_libraries_encoded;
          imported_libraries_encoded.reserve(imported_libraries.size());

          std::transform(
              std::begin(imported_libraries), std::end(imported_libraries),
              std::back_inserter(imported_libraries_encoded),
              &safe_string);
          return imported_libraries_encoded;
        },
        "Return binary's imported libraries (name)"_doc,
        "(self) -> list[Union[str,bytes]]"_p)

    .def_prop_ro("symbols",
        nb::overload_cast<>(&Binary::symbols),
        "Return an iterator over the binary's abstract " RST_CLASS_REF(lief.Symbol) ""_doc,
        nb::keep_alive<0, 1>())

    .def("has_symbol",
        &Binary::has_symbol,
        "Check if a " RST_CLASS_REF(lief.Symbol) " with the given name exists"_doc,
        "symbol_name"_a)

    .def("get_symbol",
        nb::overload_cast<const std::string&>(&Binary::get_symbol),
        R"delim(
        Return the :class:`~lief.Symbol` from the given ``name``.

        If the symbol can't be found, it returns None.
        )delim"_doc,
        "symbol_name"_a,
        nb::rv_policy::reference_internal)

    .def("get_function_address",
        [] (const Binary& self, const std::string& name) {
          return error_or(&Binary::get_function_address, self, name);
        },
        "Return the address of the given function name"_doc,
        "function_name"_a)

    .def("patch_address",
        nb::overload_cast<uint64_t, const std::vector<uint8_t>&, Binary::VA_TYPES>(&Binary::patch_address),
        R"delim(
        Patch the address with the given list of bytes.
        The virtual address is specified in the first argument and the content in the second (as a list of bytes).

        If the underlying binary is a PE, one can specify if the virtual address is a :attr:`~lief.Binary.VA_TYPES.RVA` or
        a :attr:`~lief.Binary.VA_TYPES.VA`. By default, it is set to :attr:`~lief.Binary.VA_TYPES.AUTO`.
        )delim"_doc,
        "address"_a, "patch_value"_a, "va_type"_a = Binary::VA_TYPES::AUTO)

    .def("patch_address",
        nb::overload_cast<uint64_t, uint64_t, size_t, Binary::VA_TYPES>(&Binary::patch_address),
        R"delim(
        Patch the address with the given integer value.
        The virtual address is specified in the first argument, the integer in the second and the integer's size of in third one.

        If the underlying binary is a PE, one can specify if the virtual address is a :attr:`~lief.Binary.VA_TYPES.RVA` or
        a :attr:`~lief.Binary.VA_TYPES.VA`. By default, it is set to :attr:`~lief.Binary.VA_TYPES.AUTO`.
        )delim"_doc,
        "address"_a, "patch_value"_a, "size"_a = 8, "va_type"_a = Binary::VA_TYPES::AUTO)


    .def("get_content_from_virtual_address",
        [] (const Binary& self, uint64_t va, size_t size, Binary::VA_TYPES type) {
        const span<const uint8_t> content = self.get_content_from_virtual_address(va, size, type);
        return nb::memoryview::from_memory(content.data(), content.size());
       },
       R"delim(
       Return the content located at the provided virtual address.
       The virtual address is specified in the first argument and size to read (in bytes) in the second.

       If the underlying binary is a PE, one can specify if the virtual address is a :attr:`~lief.Binary.VA_TYPES.RVA` or
       a :attr:`~lief.Binary.VA_TYPES.VA`. By default, it is set to :attr:`~lief.Binary.VA_TYPES.AUTO`.
       )delim"_doc,
       "virtual_address"_a, "size"_a, "va_type"_a = Binary::VA_TYPES::AUTO)

    .def_prop_ro("abstract",
        [] (nb::object& self) -> nb::object {
          auto* ab = nb::cast<LIEF::Binary*>(self);
          const nb::handle base_type = nb::type<LIEF::Binary>();
          nb::object py_inst = nb::inst_reference(base_type, ab, self);
          nb::inst_set_state(py_inst, /*ready=*/true, /*destruct=*/false);
          return py_inst;
        },
        R"delim(
        Return the abstract representation of the current binary (:class:`lief.Binary`)
        )delim"_doc,
        "abstract(self) -> lief.Binary"_p,
        nb::rv_policy::reference_internal)

    .def_prop_ro("concrete",
        [] (nb::object& self) {
          return nb::cast(nb::cast<LIEF::Binary*>(self));
        },
        R"delim(
        The *concrete* representation of the binary. Basically, this property cast a :class:`lief.Binary`
        into a :class:`lief.PE.Binary`, :class:`lief.ELF.Binary` or :class:`lief.MachO.Binary`.

        See also: :attr:`lief.Binary.abstract`
        )delim"_doc,
        "concrete(self) -> lief.ELF.Binary | lief.PE.Binary | lief.MachO.Binary"_p,
        nb::rv_policy::reference)

    .def_prop_ro("ctor_functions",
        &Binary::ctor_functions,
        "Constructor functions that are called prior to any other functions"_doc)

    .def("xref",
        &Binary::xref,
        "Return all **virtual addresses** that *use* the ``address`` given in parameter"_doc,
        "virtual_address"_a)

    .def("offset_to_virtual_address",
        [] (const Binary& self, uint64_t offset, uint64_t slide) {
          return error_or(&Binary::offset_to_virtual_address, self, offset, slide);
        },
        "Convert an offset into a virtual address."_doc,
        "offset"_a, "slide"_a = 0)

    .def_prop_ro("imagebase",
        &Binary::imagebase,
        "Default image base (i.e. if the ASLR is not enabled)"_doc)

    .def_prop_ro("original_size",
        nb::overload_cast<>(&LIEF::Binary::original_size, nb::const_),
        "Original size of the binary"_doc)

    LIEF_DEFAULT_STR(Binary);

}
}
