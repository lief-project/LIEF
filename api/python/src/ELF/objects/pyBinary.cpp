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

#include <nanobind/operators.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include "nanobind/extra/memoryview.hpp"

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Builder.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryArray.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/ELF/DynamicEntryRpath.hpp"
#include "LIEF/ELF/DynamicEntryRunPath.hpp"
#include "LIEF/ELF/DynamicSharedObject.hpp"
#include "LIEF/ELF/GnuHash.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionDefinition.hpp"
#include "LIEF/ELF/SymbolVersionRequirement.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"
#include "LIEF/ELF/SysvHash.hpp"

#include "pyIterator.hpp"
#include "pyErr.hpp"
#include "pySafeString.hpp"

namespace LIEF::ELF::py {
using namespace LIEF::py;

template<>
void create<Binary>(nb::module_& m) {
  nb::class_<Binary, LIEF::Binary> bin(m, "Binary",
  R"delim(
  Class which represents an ELF binary
  )delim"_doc);

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

  init_ref_iterator<Binary::it_symbols>(bin, "it_dyn_symtab_symbols");
  init_ref_iterator<Binary::it_dynamic_symbols>(bin, "it_symbols");        // For it_dynamic_symbols / it_symtab_symbols
  init_ref_iterator<Binary::it_exported_symbols>(bin, "it_filter_symbols"); // For it_imported_symbols

  nb::enum_<Binary::PHDR_RELOC>(bin, "PHDR_RELOC", R"delim(
    This enum describes the different ways to relocate the segments table.
    )delim"_doc)
    .value("AUTO", Binary::PHDR_RELOC::AUTO,
           R"delim(
           Defer the choice of the layout to LIEF.
           )delim"_doc)
    .value("PIE_SHIFT", Binary::PHDR_RELOC::PIE_SHIFT,
           R"delim(
           The content of the binary right after the segments table is shifted
           and the relocations are updated accordingly.
           This kind of shift only works with PIE binaries.
           )delim"_doc)
    .value("BSS_END", Binary::PHDR_RELOC::BSS_END,
           R"delim(
           The new segments table is relocated right after the first bss-like
           segments.
           )delim"_doc)
    .value("FILE_END", Binary::PHDR_RELOC::BINARY_END,
           R"delim(
           The new segments table is relocated at the end of the binary.
           )delim"_doc)
    .value("SEGMENT_GAP", Binary::PHDR_RELOC::SEGMENT_GAP,
           R"delim(
           The new segments table is relocated between two LOAD segments.
           This kind of relocation is only doable when there is an alignment
           enforcement.
           )delim"_doc);

  bin
    .def_prop_ro("type",
        &Binary::type,
        "Return the binary's " RST_CLASS_REF(lief.ELF.ELF_CLASS) ""_doc)

    .def_prop_ro("header",
        nb::overload_cast<>(&Binary::header),
        "Return " RST_CLASS_REF(lief.ELF.Header) " object"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("sections",
        nb::overload_cast<>(&Binary::sections),
        "Return an iterator over binary's " RST_CLASS_REF(lief.ELF.Section) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("segments",
        nb::overload_cast<>(&Binary::segments),
        "Return an iterator to binary's " RST_CLASS_REF(lief.ELF.Segment) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("dynamic_entries",
        nb::overload_cast<>(&Binary::dynamic_entries),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.DynamicEntry) " entries as a list"_doc,
        nb::keep_alive<0, 1>())

    .def("add",
        nb::overload_cast<const DynamicEntry&>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.DynamicEntry) " in the binary"_doc,
        "dynamic_entry",
        nb::rv_policy::reference_internal)

    .def_prop_ro("symtab_symbols",
        nb::overload_cast<>(&Binary::symtab_symbols),
        "Return an iterator to static  " RST_CLASS_REF(lief.ELF.Symbol) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("dynamic_symbols",
        nb::overload_cast<>(&Binary::dynamic_symbols),
        "Return an iterator to dynamic  " RST_CLASS_REF(lief.ELF.Symbol) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("symbols",
        nb::overload_cast<>(&Binary::symbols),
        "Return an iterator over both **static** and **dynamic**  " RST_CLASS_REF(lief.ELF.Symbol) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("exported_symbols",
        nb::overload_cast<>(&Binary::exported_symbols),
        "Return dynamic " RST_CLASS_REF(lief.ELF.Symbol) " which are exported"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("imported_symbols",
        nb::overload_cast<>(&Binary::imported_symbols),
        "Return dynamic  " RST_CLASS_REF(lief.ELF.Symbol) " which are imported"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("dynamic_relocations",
        nb::overload_cast<>(&Binary::dynamic_relocations),
        "Return an iterator over dynamics " RST_CLASS_REF(lief.ELF.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def("add_dynamic_relocation",
        &Binary::add_dynamic_relocation, R"delim(
        Add a new *dynamic* relocation.

        We consider a dynamic relocation as a relocation which is not plt-related.

        See: :meth:`lief.ELF.Binary.add_pltgot_relocation`
        )delim"_doc,
        "relocation"_a,
        nb::rv_policy::reference_internal)

    .def("add_pltgot_relocation",
        &Binary::add_pltgot_relocation, R"delim(
        Add a .plt.got relocation. This kind of relocation is usually
        associated with a PLT stub that aims at resolving the underlying symbol.

        See: :meth:`lief.ELF.Binary.add_dynamic_relocation`
        )delim"_doc,
        "relocation"_a,
        nb::rv_policy::reference_internal)

    .def("add_object_relocation",
        &Binary::add_object_relocation,
        R"delim(
        Add relocation for object file (.o)

        The first parameter is the section to add while the second parameter
        is the :class:`~lief.ELF.Section` associated with the relocation.

        If there is an error, this function returns a nullptr. Otherwise, it returns
        the relocation added.",
        )delim"_doc,
        "relocation"_a, "section"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("pltgot_relocations",
        nb::overload_cast<>(&Binary::pltgot_relocations),
        "Return an iterator over PLT/GOT " RST_CLASS_REF(lief.ELF.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("object_relocations",
        nb::overload_cast<>(&Binary::object_relocations),
        "Return an iterator over object " RST_CLASS_REF(lief.ELF.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("relocations",
        nb::overload_cast<>(&Binary::relocations),
        "Return an iterator over **all** " RST_CLASS_REF(lief.ELF.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("symbols_version",
        nb::overload_cast<>(&Binary::symbols_version),
        "Return an iterator " RST_CLASS_REF(lief.ELF.SymbolVersion) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("symbols_version_requirement",
        nb::overload_cast<>(&Binary::symbols_version_requirement),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.SymbolVersionRequirement) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("symbols_version_definition",
        nb::overload_cast<>(&Binary::symbols_version_definition),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.SymbolVersionDefinition) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("use_gnu_hash",
        &Binary::use_gnu_hash,
        "``True`` if GNU hash is used"_doc)

    .def_prop_ro("gnu_hash",
        &Binary::gnu_hash,
        "Return the " RST_CLASS_REF(lief.ELF.GnuHash) " object\n\n"
        "Hash are used by the loader to speed up symbols resolution (GNU Version)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("use_sysv_hash",
        &Binary::use_sysv_hash,
        "``True`` if SYSV hash is used")

    .def_prop_ro("sysv_hash",
        &Binary::sysv_hash,
        "Return the " RST_CLASS_REF(lief.ELF.SysvHash) " object\n\n"
        "Hash are used by the loader to speed up symbols resolution (SYSV version)"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("imagebase",
        &Binary::imagebase,
       "Return the program image base. (e.g. ``0x400000``)"_doc)

    .def_prop_ro("virtual_size",
        &Binary::virtual_size,
       "Return the size of the mapped binary"_doc)

    .def_prop_ro("is_pie",
        &Binary::is_pie,
        R"delim(
        Check if the binary has been compiled with `-fpie -pie` flags

        To do so we check if there is a `PT_INTERP` segment and if
        the binary type is `ET_DYN` (Shared object)
        )delim"_doc)

    .def_prop_ro("has_interpreter",
        &Binary::has_interpreter,
       "Check if the binary uses a loader (also named linker or interpreter)"_doc)

    .def_prop_ro("functions",
        &Binary::functions,
       "List of the functions found the in the binary"_doc)

    .def_prop_rw("interpreter",
        nb::overload_cast<>(&Binary::interpreter, nb::const_),
        nb::overload_cast<const std::string&>(&Binary::interpreter),
       "ELF interpreter (loader) if any. (e.g. ``/lib64/ld-linux-x86-64.so.2``)"_doc)

    .def("section_from_offset",
        nb::overload_cast<uint64_t, bool>(&Binary::section_from_offset),
        R"delim(
        Return the :class:`~lief.ELF.Section` which encompasses the given offset.
        It returns None if a section can't be found.

        If ``skip_nobits`` is set (which is the case by default), this function won't
        consider sections for which the type is ``SHT_NOBITS`` (like ``.bss, .tbss, ...``)
        )delim"_doc,
        "offset"_a, "skip_nobits"_a = true,
        nb::rv_policy::reference_internal)

    .def("section_from_virtual_address",
        nb::overload_cast<uint64_t, bool>(&Binary::section_from_virtual_address),
        R"delim(
        Return the :class:`~lief.ELF.Section` which encompasses the given virtual address.
        It returns None if a section can't be found.

        If ``skip_nobits`` is set (which is the case by default), this function won't
        consider sections for which the type is ``SHT_NOBITS`` (like ``.bss, .tbss, ...``)
        )delim"_doc,
        "address"_a, "skip_nobits"_a = true,
        nb::rv_policy::reference_internal)

    .def("segment_from_virtual_address",
        nb::overload_cast<uint64_t>(&Binary::segment_from_virtual_address),
        R"delim(
        Return the :class:`~lief.ELF.Segment` which encompasses the given virtual address.
        It returns None if a segment can't be found.
        )delim"_doc,
        "address"_a,
        nb::rv_policy::reference_internal)

    .def("segment_from_offset",
        nb::overload_cast<uint64_t>(&Binary::segment_from_offset),
        R"delim(
        Return the :class:`~lief.ELF.Segment` which encompasses the given offset.
        It returns None if a segment can't be found.
        )delim"_doc,
        "offset"_a,
        nb::rv_policy::reference_internal)

    .def("get",
        nb::overload_cast<DynamicEntry::TAG>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.DynamicEntry` from the given
        :class:`~lief.ELF.DynamicEntry.TAG`.

        It returns None if the dynamic entry can't be found.
        )delim"_doc,
        "tag"_a,
        nb::rv_policy::reference_internal)

    .def("get",
        nb::overload_cast<Segment::TYPE>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.Segment` from the given
        :class:`~lief.ELF.SEGMENT_TYPES`

        It returns None if the segment can't be found.
        )delim"_doc,
        "type"_a,
        nb::rv_policy::reference_internal)

    .def("get",
        nb::overload_cast<Note::TYPE>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.Note` from the given
        :class:`~lief.ELF.Note.TYPE`.

        It returns None if the note can't be found.
        )delim"_doc,
        "type"_a,
        nb::rv_policy::reference_internal)

    .def("get",
        nb::overload_cast<Section::TYPE>(&Binary::get),
        R"delim(
        Return the first binary's :class:`~lief.ELF.Section` from the given
        :class:`~lief.ELF.ELF_SECTION_TYPES`

        It returns None if the section can't be found.
        )delim"_doc,
        "type"_a,
        nb::rv_policy::reference_internal)

    .def("has",
        nb::overload_cast<DynamicEntry::TAG>(&Binary::has, nb::const_),
        R"delim(
        Check if it exists a :class:`~lief.ELF.DynamicEntry` with the given
        :class:`~lief.ELF.DynamicEntry.TAG`
        )delim"_doc,
        "tag"_a)

    .def("has",
        nb::overload_cast<Segment::TYPE>(&Binary::has, nb::const_),
        "Check if a " RST_CLASS_REF(lief.ELF.Segment) " of *type* (" RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) ") exists"_doc,
        "type"_a)

    .def("has",
        nb::overload_cast<Note::TYPE>(&Binary::has, nb::const_),
        "Check if a " RST_CLASS_REF(lief.ELF.Note) " of *type* (" RST_CLASS_REF(lief.ELF.Note.TYPE) ") exists"_doc,
        "type"_a)

    .def("has",
        nb::overload_cast<Section::TYPE>(&Binary::has, nb::const_),
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " of *type* (" RST_CLASS_REF(lief.ELF.SECTION_TYPES) ") exists"_doc,
        "type"_a)

    .def("patch_pltgot",
        nb::overload_cast<const std::string&, uint64_t>(&Binary::patch_pltgot),
        "Patch the imported symbol's name with the ``address``"_doc,
        "symbol_name"_a, "address"_a)

    .def("patch_pltgot",
        nb::overload_cast<const Symbol&, uint64_t>(&Binary::patch_pltgot),
        "Patch the imported " RST_CLASS_REF(lief.ELF.Symbol) " with the ``address``"_doc,
        "symbol"_a, "address"_a)

    .def("dynsym_idx",
        nb::overload_cast<const std::string&>(&Binary::dynsym_idx, nb::const_),
        R"doc(
        Get the symbol index in the **dynamic** symbol from the given name or
        return -1 if the symbol does not exist.
        )doc"_doc, "name"_a)

    .def("dynsym_idx",
        nb::overload_cast<const Symbol&>(&Binary::dynsym_idx, nb::const_),
        R"doc(
        Get the symbol index in the **dynamic** symbol table for the given symbol
        or return -1 if the symbol does not exist
        )doc"_doc, "symbol"_a)

    .def("symtab_idx",
        nb::overload_cast<const std::string&>(&Binary::symtab_idx, nb::const_),
        R"doc(
        Get the symbol index in the ``.symtab`` section from the given name or
        return -1 if the symbol does not exist.
        )doc"_doc, "name"_a)

    .def("symtab_idx",
        nb::overload_cast<const Symbol&>(&Binary::symtab_idx, nb::const_),
        R"doc(
        Get the symbol index in the ``.symtab`` section or return -1 if the
        symbol does not exist
        )doc"_doc, "symbol"_a)

    .def("has_section",
        &Binary::has_section,
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " with the given name exists in the binary"_doc,
        "section_name"_a)

    .def("has_section_with_offset",
        &Binary::has_section_with_offset,
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " that encompasses the given offset exists"_doc,
        "offset"_a)

    .def("has_section_with_va",
        &Binary::has_section_with_va,
        "Check if a " RST_CLASS_REF(lief.ELF.Section) " that encompasses the given virtual address exists"_doc,
        "virtual_address"_a)

    .def("get_section",
        nb::overload_cast<const std::string&>(&Binary::get_section),
        R"delim(
        Return the :class:`~lief.ELF.Section` with the given ``name``

        It returns None if the section can't be found.
        )delim"_doc,
        "section_name"_a,
        nb::rv_policy::reference_internal)

    .def("add_symtab_symbol",
        &Binary::add_symtab_symbol,
        "Add a **static** " RST_CLASS_REF(lief.ELF.Symbol) " to the binary"_doc,
        "symbol"_a,
        nb::rv_policy::reference_internal)

    .def("add_dynamic_symbol",
        nb::overload_cast<const Symbol&, const SymbolVersion*>(&Binary::add_dynamic_symbol),
        R"delim(
        Add a **dynamic** :class:`~lief.ELF.Symbol` to the binary

        The function also takes an optional :class:`lief.ELF.SymbolVersion`
        )delim"_doc,
        "symbol"_a, "symbol_version"_a = nullptr,
        nb::rv_policy::reference_internal)

    .def("virtual_address_to_offset",
        [] (const Binary& self, uint64_t address) {
          return error_or(&Binary::virtual_address_to_offset, self, address);
        },
        "Convert the virtual address to a file offset"_doc,
        "virtual_address"_a)

    .def("add",
        nb::overload_cast<const Section&, bool>(&Binary::add),
        R"delim(
        Add the given :class:`~lief.ELF.Section` to the binary.

        If the section does not aim at being loaded in memory,
        the ``loaded`` parameter has to be set to ``False`` (default: ``True``)
        )delim"_doc,
        "section"_a, "loaded"_a = true,
        nb::rv_policy::reference_internal)

    .def("add",
        nb::overload_cast<const Segment&, uint64_t>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.Segment) " in the binary"_doc,
        "segment"_a, "base"_a = 0,
        nb::rv_policy::reference_internal)

    .def("add",
        nb::overload_cast<const Note&>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.Note) " in the binary"_doc,
        "note"_a,
        nb::rv_policy::reference_internal)

    .def("replace",
        nb::overload_cast<const Segment&, const Segment&, uint64_t>(&Binary::replace),
        R"delim(
        Replace the :class:`~lief.ELF.Segment` given in 2nd parameter with the
        :class:`~lief.ELF.Segment` given in the first parameter and return the updated segment.

        .. warning::

            The ``original_segment`` is no longer valid after this function
        )delim"_doc,
        "new_segment"_a, "original_segment"_a, "base"_a = 0,
        nb::rv_policy::reference_internal)

    .def("extend",
        nb::overload_cast<const Segment&, uint64_t>(&Binary::extend),
        "Extend the given given " RST_CLASS_REF(lief.ELF.Segment) " by the given size"_doc,
        "segment"_a, "size"_a,
        nb::rv_policy::reference_internal)

    .def("extend",
        nb::overload_cast<const Section&, uint64_t>(&Binary::extend),
        "Extend the given given " RST_CLASS_REF(lief.ELF.Section) " by the given size"_doc,
        "segment"_a, "size"_a,
        nb::rv_policy::reference_internal)

    .def("remove",
        nb::overload_cast<const DynamicEntry&>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DynamicEntry) " from the dynamic table"_doc,
        "dynamic_entry"_a)

    .def("remove",
        nb::overload_cast<DynamicEntry::TAG>(&Binary::remove),
        "Remove **all** the " RST_CLASS_REF(lief.ELF.DynamicEntry) " with the given " RST_CLASS_REF(lief.ELF.DynamicEntry.TAG) ""_doc,
        "tag"_a)

    .def("remove",
        nb::overload_cast<const Section&, bool>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.Section) ". The ``clear`` parameter specifies whether or not "
        "we must fill its content with ``0`` before removing"_doc,
        "section"_a, "clear"_a = false)

    .def("remove",
        nb::overload_cast<const Note&>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.Note) ""_doc,
        "note"_a)

    .def("remove",
        nb::overload_cast<Note::TYPE>(&Binary::remove),
        "Remove **all** the " RST_CLASS_REF(lief.ELF.Note) " with the given " RST_CLASS_REF(lief.ELF.Note.TYPE) ""_doc,
        "type"_a)

    .def_prop_ro("has_notes",
        &Binary::has_notes,
        "``True`` if the binary contains notes"_doc)

    .def_prop_ro("notes",
        nb::overload_cast<>(&Binary::notes),
        "Return an iterator over the " RST_CLASS_REF(lief.ELF.Note) " entries"_doc,
        nb::keep_alive<0, 1>())

    .def("strip",
        &Binary::strip,
        "Strip the binary"_doc)

    .def("permute_dynamic_symbols",
        &Binary::permute_dynamic_symbols,
        "Apply the given permutation on the dynamic symbols table"_doc,
        "permutation"_a)

    .def("write",
        nb::overload_cast<const std::string&>(&Binary::write),
        "Rebuild the binary and write it in a file"_doc,
        "output"_a,
        nb::rv_policy::reference_internal)

    .def("write",
        nb::overload_cast<const std::string&, Builder::config_t>(&Binary::write),
        "Rebuild the binary with the given configuration and write it in a file"_doc,
        "output"_a, "config"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("last_offset_section",
        &Binary::last_offset_section,
        "Return the last offset used in binary according to **sections table**"_doc)

    .def_prop_ro("last_offset_segment",
        &Binary::last_offset_segment,
        "Return the last offset used in binary according to **segments table**"_doc)

    .def_prop_ro("next_virtual_address",
        &Binary::next_virtual_address,
        "Return the next virtual address available"_doc)

    .def("add_library",
        &Binary::add_library,
        "Add a library with the given name as dependency"_doc,
        "library_name"_a)

    .def("has_library",
        &Binary::has_library,
        "Check if the given library name exists in the current binary"_doc,
        "library_name"_a)

    .def("remove_library",
        &Binary::remove_library,
        "Remove the given library"_doc,
        "library_name"_a)

    .def("get_library",
        nb::overload_cast<const std::string&>(&Binary::get_library),
        R"delim(
        Return the :class:`~lief.ELF.DynamicEntryLibrary` with the given ``name``

        It returns None if the library can't be found.
        )delim"_doc,
        "library_name"_a,
        nb::rv_policy::reference_internal)

    .def("has_dynamic_symbol",
        &Binary::has_dynamic_symbol,
        "Check if the symbol with the given ``name`` exists in the **dynamic** symbol table"_doc,
        "symbol_name"_a)

    .def("get_dynamic_symbol",
        nb::overload_cast<const std::string&>(&Binary::get_dynamic_symbol),
        R"delim(
        Get the dynamic symbol from the given name.

        It returns None if it can't be found.
        )delim"_doc,
        "symbol_name"_a,
        nb::rv_policy::reference_internal)

    .def("has_symtab_symbol",
        &Binary::has_symtab_symbol,
        "Check if the symbol with the given ``name`` exists in the **static** symbol table"_doc,
        "symbol_name"_a)

    .def("get_symtab_symbol",
        nb::overload_cast<const std::string&>(&Binary::get_symtab_symbol),
        R"delim(
        Get the **static** symbol from the given ``name``.

        It returns None if it can't be found.
        )delim"_doc,
        "symbol_name"_a,
        nb::rv_policy::reference_internal)

    .def("get_strings",
        nb::overload_cast<const size_t>(&Binary::strings, nb::const_),
        "Return list of strings used in the current ELF file with a minimal size given in first parameter (Default: 5)\n"
        "It looks for strings in the ``.roadata`` section"_doc,
        "min_size"_a = 5,
        nb::rv_policy::move)

    .def_prop_ro("strings",
        [] (const Binary& bin) {
          const std::vector<std::string>& elf_strings = bin.strings();
          std::vector<safe_string_t> elf_strings_encoded;
          elf_strings_encoded.reserve(elf_strings.size());

          std::transform(std::begin(elf_strings), std::end(elf_strings),
                         std::back_inserter(elf_strings_encoded),
                         &safe_string);

          return elf_strings_encoded;
        },
        "Return list of strings used in the current ELF file.\n"
        "Basically this function looks for strings in the ``.roadata`` section"_doc,
        nb::rv_policy::move)

    .def("remove_symtab_symbol",
        nb::overload_cast<Symbol*>(&Binary::remove_symtab_symbol),
        "Remove the given " RST_CLASS_REF(lief.ELF.Symbol) " from the ``.symtab`` section"_doc)

    .def("remove_dynamic_symbol",
        nb::overload_cast<Symbol*>(&Binary::remove_dynamic_symbol),
        "Remove the given " RST_CLASS_REF(lief.ELF.Symbol) " from the ``.dynsym`` section"_doc)

    .def("remove_dynamic_symbol",
        nb::overload_cast<const std::string&>(&Binary::remove_dynamic_symbol),
        "Remove the " RST_CLASS_REF(lief.ELF.Symbol) " with the name given in parameter from the ``.dynsym`` section"_doc)

    .def("add_exported_function",
        &Binary::add_exported_function,
        "Create a symbol for the function at the given ``address`` and create an export"_doc,
        "address"_a, "name"_a = "",
        nb::rv_policy::reference_internal)

    .def("export_symbol",
        nb::overload_cast<const Symbol&>(&Binary::export_symbol),
        "Export the given symbol and create an entry if it doesn't exist"_doc,
        "symbol"_a,
        nb::rv_policy::reference_internal)

    .def("export_symbol",
        nb::overload_cast<const std::string&, uint64_t>(&Binary::export_symbol),
        "Export the symbol with the given name and create an entry if it doesn't exist"_doc,
        "symbol_name"_a, "value"_a = 0,
        nb::rv_policy::reference_internal)

    .def("get_relocation",
        nb::overload_cast<const std::string&>(&Binary::get_relocation),
        "Return the " RST_CLASS_REF(lief.ELF.Relocation) " associated with the given symbol name"_doc,
        "symbol_name"_a,
        nb::rv_policy::reference_internal)

    .def("get_relocation",
        nb::overload_cast<const Symbol&>(&Binary::get_relocation),
        "Return the " RST_CLASS_REF(lief.ELF.Relocation) " associated with the given " RST_CLASS_REF(lief.ELF.Symbol) ""_doc,
        "symbol"_a,
        nb::rv_policy::reference_internal)

    .def("get_relocation",
        nb::overload_cast<uint64_t>(&Binary::get_relocation),
        "Return the " RST_CLASS_REF(lief.ELF.Relocation) " associated with the given address"_doc,
        "address"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("dtor_functions",
        &Binary::dtor_functions,
        "List of the binary destructors (typically, the functions located in the ``.fini_array``)"_doc)

    .def_prop_ro("eof_offset",
        &Binary::eof_offset,
        "Return the last offset used by the ELF binary according to both, the sections table "
        "and the segments table."_doc)

    .def_prop_ro("has_overlay",
        &Binary::has_overlay,
        "True if data are appended to the end of the binary"_doc)

    .def_prop_rw("overlay",
        [] (const Binary& self) {
          const span<const uint8_t> overlay = self.overlay();
          return nb::memoryview::from_memory(overlay.data(), overlay.size());
        },
        [] (Binary& self, nb::bytes& bytes) {
          const auto* ptr = reinterpret_cast<const uint8_t*>(bytes.c_str());
          std::vector<uint8_t> buffer(ptr, ptr + bytes.size());
          self.overlay(std::move(buffer));
        },
        "Overlay data that are not a part of the ELF format"_doc)

    .def("relocate_phdr_table",
         &Binary::relocate_phdr_table,
         R"delim(
         Force relocating the segments table in a specific way
         (see: :class:`~lief.ELF.Binary.PHDR_RELOC`).

         This function can be used to enforce a specific relocation of the
         segments table. Upon successful relocation, the function returns
         the offset of the relocated segments table. Otherwise, if the function
         fails, it returns 0
         )delim"_doc, "type"_a = Binary::PHDR_RELOC::AUTO)

    .def("get_relocated_dynamic_array", &Binary::get_relocated_dynamic_array,
      R"doc(
      Return the array defined by the given tag (e.g.
      :attr:`~.DynamicEntry.TAG.INIT_ARRAY` with relocations applied (if any)
      )doc"_doc,
      "array_tag"_a
    )

    .def(nb::self += Segment(), nb::rv_policy::reference_internal)
    .def(nb::self += Section(), nb::rv_policy::reference_internal)
    .def(nb::self += DynamicEntry(), nb::rv_policy::reference_internal)
    .def("__iadd__", [] (Binary& self, const Note& note) {
        self += note;
        return &self;
    }, nb::rv_policy::reference_internal)
    .def(nb::self -= DynamicEntry(), nb::rv_policy::reference_internal)
    .def(nb::self -= DynamicEntry::TAG(), nb::rv_policy::reference_internal)
    .def("__isub__", [] (Binary& self, const Note& note) {
        self -= note;
        return &self;
    }, nb::rv_policy::reference_internal)
    .def(nb::self -= Note::TYPE(), nb::rv_policy::reference_internal)

    .def("__getitem__",
        nb::overload_cast<Segment::TYPE>(&Binary::operator[]),
        nb::rv_policy::reference_internal)

    .def("__getitem__",
        nb::overload_cast<Note::TYPE>(&Binary::operator[]),
        nb::rv_policy::reference_internal)

    .def("__getitem__",
        nb::overload_cast<DynamicEntry::TAG>(&Binary::operator[]),
        nb::rv_policy::reference_internal)

    .def("__getitem__",
        nb::overload_cast<Section::TYPE>(&Binary::operator[]),
        nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<Segment::TYPE>(&Binary::has, nb::const_),
        "Check if a " RST_CLASS_REF(lief.ELF.Segment) " of *type* (" RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) ") exists"_doc)

    .def("__contains__",
        nb::overload_cast<DynamicEntry::TAG>(&Binary::has, nb::const_),
        "Check if the " RST_CLASS_REF(lief.ELF.DynamicEntry) " associated with the given " RST_CLASS_REF(lief.ELF.DynamicEntry.TAG) " exists"_doc)

    .def("__contains__",
        nb::overload_cast<Note::TYPE>(&Binary::has, nb::const_),
        "Check if the " RST_CLASS_REF(lief.ELF.Note) " associated with the given " RST_CLASS_REF(lief.ELF.Note.TYPE) " exists"_doc)

    .def("__contains__",
        nb::overload_cast<Section::TYPE>(&Binary::has, nb::const_),
        "Check if the " RST_CLASS_REF(lief.ELF.Section) " associated with the given " RST_CLASS_REF(lief.ELF.SECTION_TYPES) " exists"_doc)

    LIEF_DEFAULT_STR(Binary);

}
}
