/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "nanobind/extra/stl/lief_span.h"
#include "nanobind/extra/stl/pathlike.h"
#include "pyIterator.hpp"
#include "nanobind/utils.hpp"

#include "LIEF/logging.hpp"

#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/Abstract/Relocation.hpp"
#include "LIEF/Abstract/Symbol.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/Abstract/Header.hpp"

#include "LIEF/Abstract/DebugInfo.hpp"

#include "LIEF/asm/Engine.hpp"
#include "LIEF/asm/Instruction.hpp"

#include "Abstract/pyDebugInfoTyHook.hpp"

namespace LIEF::py {
template<>
void create<Binary>(nb::module_& m) {
  nb::class_<Binary, Object> pybinary(m, "Binary",
    R"doc(
    Generic interface representing a binary executable.

    This class provides a unified interface across multiple binary formats
    such as ELF, PE, Mach-O, and others. It enables users to access binary
    components like headers, sections, symbols, relocations,
    and functions in a format-agnostic way.

    Subclasses (like :class:`lief.PE.Binary`) implement format-specific API
    )doc"_doc);

  nb::enum_<Binary::VA_TYPES>(pybinary, "VA_TYPES",
    "Enumeration of virtual address types used for patching and memory access."_doc
  )
  .value("AUTO", Binary::VA_TYPES::AUTO,
    "Automatically determine if the address is absolute or relative (default behavior)"_doc
  )
  .value("RVA", Binary::VA_TYPES::RVA,
    "Relative Virtual Address (RVA), offset from image base."_doc
  )
  .value("VA", Binary::VA_TYPES::VA,
    "Absolute Virtual Address."
  );

  nb::enum_<Binary::FORMATS>(pybinary, "FORMATS")
    .value("UNKNOWN", Binary::FORMATS::UNKNOWN)
    .value("ELF", Binary::FORMATS::ELF)
    .value("PE", Binary::FORMATS::PE)
    .value("MACHO", Binary::FORMATS::MACHO)
    .value("OAT", Binary::FORMATS::OAT);

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
        the :attr:`lief.PE.CodeViewPDB.filename` output (if present). One can also
        use :func:`lief.pdb.load` to manually load a PDB.

        .. warning::

            This function requires LIEF's extended version otherwise it
            **always** return ``None``
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
        nb::sig("def libraries(self) -> list[Union[str,bytes]]"))

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


    .def("get_content_from_virtual_address", &Binary::get_content_from_virtual_address,
       R"delim(
       Return the content located at the provided virtual address.
       The virtual address is specified in the first argument and size to read (in bytes) in the second.

       If the underlying binary is a PE, one can specify if the virtual address is a :attr:`~lief.Binary.VA_TYPES.RVA` or
       a :attr:`~lief.Binary.VA_TYPES.VA`. By default, it is set to :attr:`~lief.Binary.VA_TYPES.AUTO`.
       )delim"_doc,
       "virtual_address"_a, "size"_a, "va_type"_a = Binary::VA_TYPES::AUTO)

    .def("get_int_from_virtual_address",
          [] (const Binary& self, uint64_t va, size_t int_size, Binary::VA_TYPES type) -> IntOrNone {
            if (int_size == sizeof(uint8_t)) {
              return value_or_none(&Binary::get_int_from_virtual_address<uint8_t>, self, va, type);
            }

            if (int_size == sizeof(uint16_t)) {
              return value_or_none(&Binary::get_int_from_virtual_address<uint16_t>, self, va, type);
            }

            if (int_size == sizeof(uint32_t)) {
              return value_or_none(&Binary::get_int_from_virtual_address<uint32_t>, self, va, type);
            }

            if (int_size == sizeof(uint64_t)) {
              return value_or_none(&Binary::get_int_from_virtual_address<uint64_t>, self, va, type);
            }

            return nb::none();
          }, R"doc(
          Get an integer representation of the data at the given address
          )doc"_doc, "address"_a, "interger_size"_a, "type"_a = Binary::VA_TYPES::AUTO
        )

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
        nb::sig("def abstract(self) -> lief.Binary"),
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
        nb::sig("def concrete(self) -> lief.ELF.Binary | lief.PE.Binary | lief.MachO.Binary"),
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

    .def("disassemble", [] (const Binary& self, uint64_t address) {
          auto insts = self.disassemble(address);
          return nb::make_iterator<nb::rv_policy::reference_internal>(
            nb::type<Binary>(), "instructions_it", insts
          );
      }, "address"_a, nb::keep_alive<0, 1>(),
      R"doc(
      Disassemble code starting at the given virtual address.

      .. code-block:: python

        insts = binary.disassemble(0xacde, 100);
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
    )

    .def("disassemble", [] (const Binary& self, uint64_t address, size_t size) {
          auto insts = self.disassemble(address, size);
          return nb::make_iterator<nb::rv_policy::reference_internal>(
              nb::type<Binary>(), "instructions_it", insts);
      }, "address"_a, "size"_a, nb::keep_alive<0, 1>(),
      R"doc(
      Disassemble code starting at the given virtual address and with the given
      size.

      .. code-block:: python

        insts = binary.disassemble(0xacde, 100);
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
    )

    .def("disassemble", [] (const Binary& self, const std::string& function) {
          auto insts = self.disassemble(function);
          return nb::make_iterator<nb::rv_policy::reference_internal>(
              nb::type<Binary>(), "instructions_it", insts);
      }, "function_name"_a, nb::keep_alive<0, 1>(),
      R"doc(
      Disassemble code for the given symbol name

      .. code-block:: python

        insts = binary.disassemble("__libc_start_main");
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
    )

    .def("disassemble_from_bytes",
         [] (const Binary& self, const nb::bytes& buffer, uint64_t address) {
          auto insts = self.disassemble(
            reinterpret_cast<const uint8_t*>(buffer.c_str()),
            buffer.size(), address
          );
          return nb::make_iterator<nb::rv_policy::reference_internal>(
              nb::type<Binary>(), "instructions_it", insts);
      }, "buffer"_a, "address"_a = 0, nb::keep_alive<0, 1>(), nb::keep_alive<0, 2>(),
      R"doc(
      Disassemble code from the provided bytes

      .. code-block:: python

        raw = bytes(binary.get_section(".text").content)
        insts = binary.disassemble_from_bytes(raw);
        for inst in insts:
            print(inst)

      .. seealso:: :class:`lief.assembly.Instruction`
      )doc"_doc
    )

    .def("assemble",
      [] (Binary& self, uint64_t address, const std::string& Asm,
          assembly::AssemblerConfig& config)
      {
        return nb::to_bytes(self.assemble(address, Asm, config));
      }, "address"_a, "assembly"_a, "config"_a = assembly::AssemblerConfig::default_config(),
      R"doc(
      Assemble **and patch** the provided assembly code at the specified address.

      The function returns the generated assembly bytes.

      Example:

      .. code-block:: python

         bin.assemble(0x12000440, """
         xor rax, rbx;
         mov rcx, rax;
         """)

      If you need to configure the assembly engine or to define addresses for
      symbols, you can provide your own :class:`~.assembly.AssemblerConfig` instance.
      )doc"_doc
    )

    .def_prop_ro("page_size", &Binary::page_size,
      R"doc(
      Get the default memory page size according to the architecture and the
      format of the current binary
      )doc"_doc
    )

    .def("load_debug_info", [] (Binary& self, const nb::PathLike& pathlike) {
        return self.load_debug_info(pathlike);
      }, "path"_a, nb::rv_policy::reference_internal,
      R"doc(
      Load and associate an external debug file (e.g., DWARF or PDB) with this
      binary.

      This method attempts to load the debug information from the file located
      at the given path, and binds it to the current binary instance. If
      successful, it returns the loaded :class:`~.DebugInfo` object.

      .. warning::

        It is the caller's responsibility to ensure that the debug file is
        compatible with the binary. Incorrect associations may lead to
        inconsistent or invalid results.

      .. note::

          This function does not verify that the debug file matches the binary's
          unique identifier (e.g., build ID, GUID).
      )doc"_doc
    )

    .def_prop_ro("virtual_size",
      &Binary::virtual_size,
      "Size of the binary when mapped in memory"_a)

    LIEF_DEFAULT_STR(Binary);

}
}
