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
#include <algorithm>

#include "pyIterators.hpp"
#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Binary.hpp"

#include "pyErr.hpp"
#include "pyELF.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using no_const_getter = T (Binary::*)(void);

template<class T, class P>
using no_const_func = T (Binary::*)(P);

template<class T>
using getter_t = T (Binary::*)(void) const;

template<class T>
using setter_t = void (Binary::*)(T);


template<>
void create<Binary>(py::module& m) {
  // Binary object
  py::class_<Binary, LIEF::Binary> bin(m, "Binary", R"delim(
  Class which represents an ELF binary
  )delim");

  init_ref_iterator<Binary::it_notes>(bin, "it_notes");
  init_ref_iterator<Binary::it_symbols_version_requirement>(bin, "it_symbols_version_requirement");
  init_ref_iterator<Binary::it_symbols_version_definition>(bin, "it_symbols_version_definition");
  init_ref_iterator<Binary::it_segments>(bin, "it_segments");
  init_ref_iterator<Binary::it_sections>(bin, "it_sections");
  init_ref_iterator<Binary::it_dynamic_entries>(bin, "it_dynamic_entries");
  init_ref_iterator<Binary::it_symbols_version>(bin, "it_symbols_version");
  // We don't need to register it_object_relocations, it_dynamic_relocations
  // as it it the same underlying type
  init_ref_iterator<Binary::it_pltgot_relocations>(bin, "it_filter_relocation");
  init_ref_iterator<Binary::it_relocations>(bin, "it_relocations");

  init_ref_iterator<Binary::it_symbols>(bin,          "it_dyn_static_symbols");
  init_ref_iterator<Binary::it_dynamic_symbols>(bin,  "it_symbols");        // For it_dynamic_symbols / it_static_symbols
  init_ref_iterator<Binary::it_exported_symbols>(bin, "it_filter_symbols"); // For it_imported_symbols




  bin
    .def_property_readonly("type",
        &Binary::type,
        "Return the binary's " RST_CLASS_REF(lief.ELF.ELF_CLASS) "")

    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&Binary::header),
        "Return " RST_CLASS_REF(lief.ELF.Header) " object",
        py::return_value_policy::reference_internal)

    .def_property_readonly("sections",
        static_cast<no_const_getter<Binary::it_sections>>(&Binary::sections),
        "Return an iterator over binary's " RST_CLASS_REF(lief.ELF.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("segments",
        static_cast<no_const_getter<Binary::it_segments>>(&Binary::segments),
        "Return an iterator to binary's " RST_CLASS_REF(lief.ELF.Segment) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_entries",
        static_cast<no_const_getter<Binary::it_dynamic_entries>>(&Binary::dynamic_entries),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.DynamicEntry) " entries as a list",
        py::return_value_policy::reference_internal)

    .def("add",
        static_cast<DynamicEntry& (Binary::*)(const DynamicEntry&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.DynamicEntry) " in the binary",
        "dynamic_entry",
        py::return_value_policy::reference)

    .def_property_readonly("static_symbols",
        static_cast<no_const_getter<Binary::it_static_symbols>>(&Binary::static_symbols),
        "Return an iterator to static  " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_symbols",
        static_cast<no_const_getter<Binary::it_dynamic_symbols>>(&Binary::dynamic_symbols),
        "Return an iterator to dynamic  " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols",
        static_cast<no_const_getter<Binary::it_symbols>>(&Binary::symbols),
        "Return an iterator over both **static** and **dynamic**  " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_symbols",
        static_cast<no_const_getter<Binary::it_exported_symbols>>(&Binary::exported_symbols),
        "Return dynamic " RST_CLASS_REF(lief.ELF.Symbol) " which are exported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("imported_symbols",
        static_cast<no_const_getter<Binary::it_imported_symbols>>(&Binary::imported_symbols),
        "Return dynamic  " RST_CLASS_REF(lief.ELF.Symbol) " which are imported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_relocations",
        static_cast<no_const_getter<Binary::Binary::it_dynamic_relocations>>(&Binary::dynamic_relocations),
        "Return an iterator over dynamics " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def("add_dynamic_relocation",
        &Binary::add_dynamic_relocation, R"delim(
        Add a new *dynamic* relocation.

        We consider a dynamic relocation as a relocation which is not plt-related.

        See: :meth:`lief.ELF.Binary.add_pltgot_relocation`
        )delim",
        "relocation"_a,
        py::return_value_policy::reference)

    .def("add_pltgot_relocation",
        &Binary::add_pltgot_relocation, R"delim(
        Add a .plt.got relocation. This kind of relocation is usually
        associated with a PLT stub that aims at resolving the underlying symbol.

        See: :meth:`lief.ELF.Binary.add_dynamic_relocation`
        )delim",
        "relocation"_a,
        py::return_value_policy::reference)

    .def("add_object_relocation",
        &Binary::add_object_relocation,
        R"delim(
        Add relocation for object file (.o)

        The first parameter is the section to add while the second parameter
        is the :class:`~lief.ELF.Section` associated with the relocation.

        If there is an error, this function returns a nullptr. Otherwise, it returns
        the relocation added.",
        )delim",
        "relocation"_a, "section"_a,
        py::return_value_policy::reference)

    .def_property_readonly("pltgot_relocations",
        static_cast<no_const_getter<Binary::it_pltgot_relocations>>(&Binary::pltgot_relocations),
        "Return an iterator over PLT/GOT " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("object_relocations",
        static_cast<no_const_getter<Binary::it_object_relocations>>(&Binary::object_relocations),
        "Return an iterator over object " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<no_const_getter<Binary::it_relocations>>(&Binary::relocations),
        "Return an iterator over **all** " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version",
        static_cast<no_const_getter<Binary::it_symbols_version>>(&Binary::symbols_version),
        "Return an iterator " RST_CLASS_REF(lief.ELF.SymbolVersion) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version_requirement",
        static_cast<no_const_getter<Binary::it_symbols_version_requirement>>(&Binary::symbols_version_requirement),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.SymbolVersionRequirement) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version_definition",
        static_cast<no_const_getter<Binary::it_symbols_version_definition>>(&Binary::symbols_version_definition),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.SymbolVersionDefinition) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("use_gnu_hash",
        &Binary::use_gnu_hash,
        "``True`` if GNU hash is used")

    .def_property_readonly("gnu_hash",
        &Binary::gnu_hash,
        "Return the " RST_CLASS_REF(lief.ELF.GnuHash) " object\n\n"
        "Hash are used by the loader to speed up symbols resolution (GNU Version)",
        py::return_value_policy::reference_internal)

    .def_property_readonly("use_sysv_hash",
        &Binary::use_sysv_hash,
        "``True`` if SYSV hash is used")

    .def_property_readonly("sysv_hash",
        &Binary::sysv_hash,
        "Return the " RST_CLASS_REF(lief.ELF.SysvHash) " object\n\n"
        "Hash are used by the loader to speed up symbols resolution (SYSV version)",
        py::return_value_policy::reference_internal)

   .def_property_readonly("imagebase",
        &Binary::imagebase,
       "Return the program image base. (e.g. ``0x400000``)")

   .def_property_readonly("virtual_size",
        &Binary::virtual_size,
       "Return the size of the mapped binary")

   .def_property_readonly("is_pie",
        &Binary::is_pie,
        R"delim(
        Check if the binary has been compiled with `-fpie -pie` flags

        To do so we check if there is a `PT_INTERP` segment and if
        the binary type is `ET_DYN` (Shared object)
        )delim")

   .def_property_readonly("has_interpreter",
        &Binary::has_interpreter,
       "Check if the binary uses a loader (also named linker or interpreter)")

   .def_property_readonly("functions",
        &Binary::functions,
       "List of the functions found the in the binary")

   .def_property("interpreter",
        static_cast<getter_t<const std::string&>>(&Binary::interpreter),
        static_cast<setter_t<const std::string&>>(&Binary::interpreter),
       "ELF interpreter (loader) if any. (e.g. ``/lib64/ld-linux-x86-64.so.2``)")

    .def("section_from_offset",
        static_cast<Section*(Binary::*)(uint64_t, bool)>(&Binary::section_from_offset),
        R"delim(
        Return the :class:`~lief.ELF.Section` which encompasses the given offset.
        It returns None if a section can't be found.

        If ``skip_nobits`` is set (which is the case by default), this function won't
        consider sections for which the type is ``SHT_NOBITS`` (like ``.bss, .tbss, ...``)
        )delim",
        "offset"_a, "skip_nobits"_a = true,
        py::return_value_policy::reference)

    .def("section_from_virtual_address",
        static_cast<Section*(Binary::*)(uint64_t, bool)>(&Binary::section_from_virtual_address),
        R"delim(
        Return the :class:`~lief.ELF.Section` which encompasses the given virtual address.
        It returns None if a section can't be found.

        If ``skip_nobits`` is set (which is the case by default), this function won't
        consider sections for which the type is ``SHT_NOBITS`` (like ``.bss, .tbss, ...``)
        )delim",
        "address"_a, "skip_nobits"_a = true,
        py::return_value_policy::reference)

    .def("segment_from_virtual_address",
        static_cast<no_const_func<Segment*, uint64_t>>(&Binary::segment_from_virtual_address),
        R"delim(
        Return the :class:`~lief.ELF.Segment` which encompasses the given virtual address.
        It returns None if a segment can't be found.
        )delim",
        "address"_a,
        py::return_value_policy::reference)

    .def("segment_from_offset",
        static_cast<no_const_func<Segment*, uint64_t>>(&Binary::segment_from_offset),
        R"delim(
        Return the :class:`~lief.ELF.Segment` which encompasses the given offset.
        It returns None if a segment can't be found.
        )delim",
        "offset"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<DynamicEntry*, DYNAMIC_TAGS>>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.DynamicEntry` from the given
        :class:`~lief.ELF.DYNAMIC_TAGS`.

        It returns None if the dynamic entry can't be found.
        )delim",
        "tag"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<Segment*, SEGMENT_TYPES>>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.Segment` from the given
        :class:`~lief.ELF.SEGMENT_TYPES`

        It returns None if the segment can't be found.
        )delim",
        "type"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<Note*, NOTE_TYPES>>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.Note` from the given
        :class:`~lief.ELF.NOTE_TYPES`.

        It returns None if the note can't be found.
        )delim",
        "type"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<Section*, ELF_SECTION_TYPES>>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.Section` from the given
        :class:`~lief.ELF.ELF_SECTION_TYPES`

        It returns None if the section can't be found.
        )delim",
        "type"_a,
        py::return_value_policy::reference)

    .def("has",
        static_cast<bool (Binary::*)(DYNAMIC_TAGS) const>(&Binary::has),
        R"delim(
        Check if it exists a :class:`~lief.ELF.DynamicEntry` with the given
        :class:`~lief.ELF.DYNAMIC_TAGS`
        )delim",
        "tag"_a)

    .def("has",
        static_cast<bool (Binary::*)(SEGMENT_TYPES) const>(&Binary::has),
        "Check if a " RST_CLASS_REF(lief.ELF.Segment) " of *type* (" RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) ") exists",
        "type"_a)

    .def("has",
        static_cast<bool (Binary::*)(NOTE_TYPES) const>(&Binary::has),
        "Check if a " RST_CLASS_REF(lief.ELF.Note) " of *type* (" RST_CLASS_REF(lief.ELF.NOTE_TYPES) ") exists",
        "type"_a)

    .def("has",
        static_cast<bool (Binary::*)(ELF_SECTION_TYPES) const>(&Binary::has),
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " of *type* (" RST_CLASS_REF(lief.ELF.ECTION_TYPES) ") exists",
        "type"_a)

    .def("patch_pltgot",
        static_cast<void (Binary::*) (const std::string&, uint64_t)>(&Binary::patch_pltgot),
        "Patch the imported symbol's name with the ``address``",
        "symbol_name"_a, "address"_a)

    .def("patch_pltgot",
        static_cast<void (Binary::*) (const Symbol&, uint64_t)>(&Binary::patch_pltgot),
        "Patch the imported " RST_CLASS_REF(lief.ELF.Symbol) " with the ``address``",
        "symbol"_a, "address"_a)

    .def("has_section",
        &Binary::has_section,
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " with the given name exists in the binary",
        "section_name"_a)

    .def("has_section_with_offset",
        &Binary::has_section_with_offset,
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " that encompasses the given offset exists",
        "offset"_a)

    .def("has_section_with_va",
        &Binary::has_section_with_va,
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " that encompasses the given virtual address exists",
        "virtual_address"_a)

    .def("get_section",
        static_cast<no_const_func<Section*, const std::string&>>(&Binary::get_section),
        R"delim(
        Return the :class:`~lief.ELF.Section` with the given ``name``

        It returns None if the section can't be found.
        )delim",
        "section_name"_a,
        py::return_value_policy::reference)

    .def("add_static_symbol",
        &Binary::add_static_symbol,
        "Add a **static** " RST_CLASS_REF(lief.ELF.Symbol) " to the binary",
        "symbol"_a,
        py::return_value_policy::reference)

    .def("add_dynamic_symbol",
        static_cast<Symbol& (Binary::*)(const Symbol&, const SymbolVersion*)>(&Binary::add_dynamic_symbol),
        R"delim(
        Add a **dynamic** :class:`~lief.ELF.Symbol` to the binary

        The function also takes an optional :class:`lief.ELF.SymbolVersion`
        )delim",
        "symbol"_a, "symbol_version"_a = nullptr,
        py::return_value_policy::reference)

    .def("virtual_address_to_offset",
        [] (const Binary& self, uint64_t address) {
          return error_or(&Binary::virtual_address_to_offset, self, address);
        },
        "Convert the virtual address to a file offset",
        "virtual_address"_a)

    .def("add",
        static_cast<Section* (Binary::*)(const Section&, bool)>(&Binary::add),
        R"delim(
        Add the given :class:`~lief.ELF.Section` to the binary.

        If the section does not aim at being loaded in memory,
        the ``loaded`` parameter has to be set to ``False`` (default: ``True``)
        )delim",
        "section"_a, "loaded"_a = true,
        py::return_value_policy::reference)

    .def("add",
        static_cast<Segment* (Binary::*)(const Segment&, uint64_t)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.Segment) " in the binary"
        "segment"_a, "base"_a = 0,
        py::return_value_policy::reference)

    .def("add",
        static_cast<Note& (Binary::*)(const Note&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.Note) " in the binary",
        "note"_a,
        py::return_value_policy::reference)

    .def("replace",
        static_cast<Segment* (Binary::*)(const Segment&, const Segment&, uint64_t)>(&Binary::replace),
        R"delim(
        Replace the :class:`~lief.ELF.Segment` given in 2nd parameter with the
        :class:`~lief.ELF.Segment` given in the first parameter and return the updated segment.

        .. warning::

            The ``original_segment`` is no longer valid after this function
        )delim",
        "new_segment"_a, "original_segment"_a, "base"_a = 0,
        py::return_value_policy::reference)

    .def("extend",
        static_cast<Segment* (Binary::*)(const Segment&, uint64_t)>(&Binary::extend),
        "Extend the given given " RST_CLASS_REF(lief.ELF.Segment) " by the given size",
        "segment"_a, "size"_a,
        py::return_value_policy::reference)

    .def("extend",
        static_cast<Section* (Binary::*)(const Section&, uint64_t)>(&Binary::extend),
        "Extend the given given " RST_CLASS_REF(lief.ELF.Section) " by the given size",
        "segment"_a, "size"_a,
        py::return_value_policy::reference)

    .def("remove",
        static_cast<void (Binary::*)(const DynamicEntry&)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DynamicEntry) " from the dynamic table",
        "dynamic_entry"_a)

    .def("remove",
        static_cast<void (Binary::*)(DYNAMIC_TAGS)>(&Binary::remove),
        "Remove **all** the " RST_CLASS_REF(lief.ELF.DynamicEntry) " with the given " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) "",
        "tag"_a)

    .def("remove",
        static_cast<void (Binary::*)(const Section&, bool)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.Section) ". The ``clear`` parameter specifies whether or not "
        "we must fill its content with ``0`` before removing",
        "section"_a, "clear"_a = false)

    .def("remove",
        static_cast<void (Binary::*)(const Note&)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.Note) "",
        "note"_a)

    .def("remove",
        static_cast<void (Binary::*)(NOTE_TYPES)>(&Binary::remove),
        "Remove **all** the " RST_CLASS_REF(lief.ELF.Note) " with the given " RST_CLASS_REF(lief.ELF.NOTE_TYPES) "",
        "type"_a)

    .def_property_readonly("has_notes",
        &Binary::has_notes,
        "``True`` if the binary contains notes")

    .def_property_readonly("notes",
        static_cast<no_const_getter<Binary::it_notes>>(&Binary::notes),
        "Return an iterator over the " RST_CLASS_REF(lief.ELF.Note) " entries",
        py::return_value_policy::reference_internal)

    .def("strip",
        &Binary::strip,
        "Strip the binary")

    .def("permute_dynamic_symbols",
        &Binary::permute_dynamic_symbols,
        "Apply the given permutation on the dynamic symbols table",
        "permutation"_a)

    .def("write",
        static_cast<void (Binary::*)(const std::string&)>(&Binary::write),
        "Rebuild the binary and write it in a file",
        "output"_a,
        py::return_value_policy::reference_internal)

    .def_property_readonly("last_offset_section",
        &Binary::last_offset_section,
        "Return the last offset used in binary according to **sections table**")

    .def_property_readonly("last_offset_segment",
        &Binary::last_offset_segment,
        "Return the last offset used in binary according to **segments table**")

    .def_property_readonly("next_virtual_address",
        &Binary::next_virtual_address,
        "Return the next virtual address available")

    .def("add_library",
        &Binary::add_library,
        "Add a library with the given name as dependency",
        "library_name"_a)

    .def("has_library",
        &Binary::has_library,
        "Check if the given library name exists in the current binary",
        "library_name"_a)

    .def("remove_library",
        &Binary::remove_library,
        "Remove the given library",
        "library_name"_a)

    .def("get_library",
        static_cast<no_const_func<DynamicEntryLibrary*, const std::string&>>(&Binary::get_library),
        R"delim(
        Return the :class:`~lief.ELF.DynamicEntryLibrary` with the given ``name``

        It returns None if the library can't be found.
        )delim",
        "library_name"_a,
        py::return_value_policy::reference)

    .def("has_dynamic_symbol",
        &Binary::has_dynamic_symbol,
        "Check if the symbol with the given ``name`` exists in the **dynamic** symbol table",
        "symbol_name"_a)

    .def("get_dynamic_symbol",
        static_cast<no_const_func<Symbol*, const std::string&>>(&Binary::get_dynamic_symbol),
        R"delim(
        Get the dynamic symbol from the given name.

        It returns None if it can't be found.
        )delim",
        "symbol_name"_a,
        py::return_value_policy::reference)

    .def("has_static_symbol",
        &Binary::has_static_symbol,
        "Check if the symbol with the given ``name`` exists in the **static** symbol table",
        "symbol_name"_a)

    .def("get_static_symbol",
        static_cast<no_const_func<Symbol*, const std::string&>>(&Binary::get_static_symbol),
        R"delim(
        Get the **static** symbol from the given ``name``.

        It returns None if it can't be found.
        )delim",
        "symbol_name"_a,
        py::return_value_policy::reference)

    .def("get_strings",
        static_cast<Binary::string_list_t (Binary::*)(const size_t) const>(&Binary::strings),
        "Return list of strings used in the current ELF file with a minimal size given in first parameter (Default: 5)\n"
        "It looks for strings in the ``.roadata`` section",
        "min_size"_a = 5,
        py::return_value_policy::move)

    .def_property_readonly("strings",
        [] (const Binary& bin) {
          return bin.strings();
        },
        "Return list of strings used in the current ELF file.\n"
        "Basically this function looks for strings in the ``.roadata`` section",
        py::return_value_policy::move)

    .def("remove_static_symbol",
        static_cast<void(Binary::*)(Symbol* s)>(&Binary::remove_static_symbol),
        "Remove the given " RST_CLASS_REF(lief.ELF.Symbol) " from the ``.symtab`` section")

    .def("add_exported_function",
        &Binary::add_exported_function,
        "Create a symbol for the function at the given ``address`` and create an export",
        "address"_a, "name"_a = "",
        py::return_value_policy::reference)

    .def("export_symbol",
        static_cast<Symbol& (Binary::*)(const Symbol&)>(&Binary::export_symbol),
        "Export the given symbol and create an entry if it doesn't exist",
        "symbol"_a,
        py::return_value_policy::reference)

    .def("export_symbol",
        static_cast<Symbol& (Binary::*)(const std::string&, uint64_t)>(&Binary::export_symbol),
        "Export the symbol with the given name and create an entry if it doesn't exist",
        "symbol_name"_a, "value"_a = 0,
        py::return_value_policy::reference)

    .def("get_relocation",
        static_cast<no_const_func<Relocation*, const std::string&>>(&Binary::get_relocation),
        "Return the " RST_CLASS_REF(lief.ELF.Relocation) " associated with the given symbol name",
        "symbol_name"_a,
        py::return_value_policy::reference)

    .def("get_relocation",
        static_cast<no_const_func<Relocation*, const Symbol&>>(&Binary::get_relocation),
        "Return the " RST_CLASS_REF(lief.ELF.Relocation) " associated with the given " RST_CLASS_REF(lief.ELF.Symbol) "",
        "symbol"_a,
        py::return_value_policy::reference)

    .def("get_relocation",
        static_cast<no_const_func<Relocation*, uint64_t>>(&Binary::get_relocation),
        "Return the " RST_CLASS_REF(lief.ELF.Relocation) " associated with the given address",
        "address"_a,
        py::return_value_policy::reference)

    .def_property_readonly("dtor_functions",
        &Binary::dtor_functions,
        "List of the binary destructors (typically, the functions located in the ``.fini_array``)")

    .def_property_readonly("eof_offset",
        &Binary::eof_offset,
        "Return the last offset used by the ELF binary according to both: the sections table "
        "and the segments table.")

    .def_property_readonly("has_overlay",
        &Binary::has_overlay,
        "True if data are appended to the end of the binary")

    .def_property("overlay",
        static_cast<getter_t<const Binary::overlay_t&>>(&Binary::overlay),
        static_cast<setter_t<Binary::overlay_t>>(&Binary::overlay),
        "Overlay data that are not a part of the ELF format")

    .def(py::self += Segment())
    .def(py::self += Section())
    .def(py::self += DynamicEntry())
    .def(py::self += Note())

    .def(py::self -= DynamicEntry())
    .def(py::self -= DYNAMIC_TAGS())

    .def(py::self -= Note())
    .def(py::self -= NOTE_TYPES())

    .def("__eq__", &Binary::operator==)
    .def("__ne__", &Binary::operator!=)
    .def("__hash__",
        [] (const Binary& binary) {
          return Hash::hash(binary);
        })

    .def("__getitem__",
        static_cast<Segment* (Binary::*)(SEGMENT_TYPES)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__getitem__",
        static_cast<Note* (Binary::*)(NOTE_TYPES)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__getitem__",
        static_cast<DynamicEntry* (Binary::*)(DYNAMIC_TAGS)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)


    .def("__getitem__",
        static_cast<Section* (Binary::*)(ELF_SECTION_TYPES)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__contains__",
        static_cast<bool (Binary::*)(SEGMENT_TYPES) const>(&Binary::has),
        "Check if a " RST_CLASS_REF(lief.ELF.Segment) " of *type* (" RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) ") exists")

    .def("__contains__",
        static_cast<bool (Binary::*)(DYNAMIC_TAGS) const>(&Binary::has),
        "Check if the " RST_CLASS_REF(lief.ELF.DynamicEntry) " associated with the given " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " exists")

    .def("__contains__",
        static_cast<bool (Binary::*)(NOTE_TYPES) const>(&Binary::has),
        "Check if the " RST_CLASS_REF(lief.ELF.Note) " associated with the given " RST_CLASS_REF(lief.ELF.NOTE_TYPES) " exists")

    .def("__contains__",
        static_cast<bool (Binary::*)(ELF_SECTION_TYPES) const>(&Binary::has),
        "Check if the " RST_CLASS_REF(lief.ELF.Section) " associated with the given " RST_CLASS_REF(lief.ELF.SECTION_TYPES) " exists")

    .def("__str__",
        [] (const Binary& binary) {
          std::ostringstream stream;
          stream << binary;
          return stream.str();
        });
}
}
}
