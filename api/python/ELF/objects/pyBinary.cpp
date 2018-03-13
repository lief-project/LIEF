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

#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/hash.hpp"
#include "LIEF/Abstract/Binary.hpp"

#include "pyELF.hpp"

template<class T>
using no_const_getter = T (Binary::*)(void);

template<class T, class P>
using no_const_func = T (Binary::*)(P);

template<class T>
using getter_t = T (Binary::*)(void) const;

template<class T>
using setter_t = void (Binary::*)(T);

void init_ELF_Binary_class(py::module& m) {

  // Binary object
  py::class_<Binary, LIEF::Binary>(m, "Binary", "ELF binary representation")
    .def(py::init<const std::string&, ELF_CLASS>())

    .def_property_readonly("type",
        &Binary::type,
        "Return the binary's " RST_CLASS_REF(lief.ELF.ELF_CLASS) "")

    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&Binary::header),
        "Return " RST_CLASS_REF(lief.ELF.Header) " object",
        py::return_value_policy::reference_internal)

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&Binary::sections),
        "Return an iterator to binary's " RST_CLASS_REF(lief.ELF.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("segments",
        static_cast<no_const_getter<it_segments>>(&Binary::segments),
        "Return an interator to binary's " RST_CLASS_REF(lief.ELF.Segment) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_entries",
        static_cast<no_const_getter<it_dynamic_entries>>(&Binary::dynamic_entries),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.DynamicEntry) " entries as a list",
        py::return_value_policy::reference_internal)

    .def("add",
        static_cast<DynamicEntry& (Binary::*)(const DynamicEntry&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.DynamicEntry) " in the binary",
        "dynamic_entry",
        py::return_value_policy::reference)

    .def_property_readonly("static_symbols",
        static_cast<no_const_getter<it_symbols>>(&Binary::static_symbols),
        "Return an iterator to static  " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_symbols",
        static_cast<no_const_getter<it_symbols>>(&Binary::dynamic_symbols),
        "Return an iterator to dynamic  " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols",
        static_cast<no_const_getter<it_symbols>>(&Binary::symbols),
        "Return an iterator over both **static** and **dynamic**  " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_symbols",
        static_cast<no_const_getter<it_exported_symbols>>(&Binary::exported_symbols),
        "Return dynamic " RST_CLASS_REF(lief.ELF.Symbol) " which are exported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("imported_symbols",
        static_cast<no_const_getter<it_imported_symbols>>(&Binary::imported_symbols),
        "Return dynamic  " RST_CLASS_REF(lief.ELF.Symbol) " which are imported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_relocations",
        static_cast<no_const_getter<it_dynamic_relocations>>(&Binary::dynamic_relocations),
        "Return an iterator over dynamics " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def("add_dynamic_relocation",
        &Binary::add_dynamic_relocation,
        py::return_value_policy::reference)

    .def("add_pltgot_relocation",
        &Binary::add_pltgot_relocation,
        py::return_value_policy::reference)

    .def_property_readonly("pltgot_relocations",
        static_cast<no_const_getter<it_pltgot_relocations>>(&Binary::pltgot_relocations),
        "Return an iterator over PLT/GOT " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("object_relocations",
        static_cast<no_const_getter<it_object_relocations>>(&Binary::object_relocations),
        "Return an iterator over object " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<no_const_getter<it_relocations>>(&Binary::relocations),
        "Return an iterator over **all** " RST_CLASS_REF(lief.ELF.Relocation) " s",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version",
        static_cast<no_const_getter<it_symbols_version>>(&Binary::symbols_version),
        "Return an iterator " RST_CLASS_REF(lief.ELF.SymbolVersion) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version_requirement",
        static_cast<no_const_getter<it_symbols_version_requirement>>(&Binary::symbols_version_requirement),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.SymbolVersionRequirement) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version_definition",
        static_cast<no_const_getter<it_symbols_version_definition>>(&Binary::symbols_version_definition),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.SymbolVersionDefinition) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("use_gnu_hash",
        &Binary::use_gnu_hash,
        "``True`` if GNU hash is used")

    .def_property_readonly("gnu_hash",
        &Binary::gnu_hash,
        "Return the " RST_CLASS_REF(lief.ELF.GnuHash) " object\n\n"
        "Hash are used by the loader to speed up symbols resolving (GNU Version)",
        py::return_value_policy::reference_internal)

    .def_property_readonly("use_sysv_hash",
        &Binary::use_sysv_hash,
        "``True`` if SYSV hash is used")

    .def_property_readonly("sysv_hash",
        &Binary::sysv_hash,
        "Return the " RST_CLASS_REF(lief.ELF.SysvHash) " object\n\n"
        "Hash are used by the loader to speed up symbols resolving (SYSV version)",
        py::return_value_policy::reference_internal)

   .def_property_readonly("imagebase",
        &Binary::imagebase,
       "Return the program image base. (e.g. ``0x400000``)")

   .def_property_readonly("virtual_size",
        &Binary::virtual_size,
       "Return the binary's size when mapped in memory")

   .def_property_readonly("is_pie",
        &Binary::is_pie,
       "``True`` if the binary is a ``pie`` one")

   .def_property_readonly("has_interpreter",
        &Binary::has_interpreter,
       "``True`` if the binary uses a loader")

   .def_property("interpreter",
        static_cast<getter_t<const std::string&>>(&Binary::interpreter),
        static_cast<setter_t<const std::string&>>(&Binary::interpreter),
       "ELF interprer (loader) if any. (e.g. ``/lib64/ld-linux-x86-64.so.2``)")

    .def("section_from_offset",
        static_cast<no_const_func<Section&, uint64_t>>(&Binary::section_from_offset),
        "Return binary's " RST_CLASS_REF(lief.ELF.Section) " which holds the offset",
        "offset"_a,
        py::return_value_policy::reference)

    .def("section_from_virtual_address",
        static_cast<no_const_func<Section&, uint64_t>>(&Binary::section_from_virtual_address),
        "Return binary's " RST_CLASS_REF(lief.ELF.Section) " which holds the given virtual address",
        "address"_a,
        py::return_value_policy::reference)

    .def("segment_from_virtual_address",
        static_cast<no_const_func<Segment&, uint64_t>>(&Binary::segment_from_virtual_address),
        "Return binary's " RST_CLASS_REF(lief.ELF.Segment) " which holds the address",
        "address"_a,
        py::return_value_policy::reference)

    .def("segment_from_offset",
        static_cast<no_const_func<Segment&, uint64_t>>(&Binary::segment_from_offset),
        "Return binary's " RST_CLASS_REF(lief.ELF.Segment) " which holds the offset",
        "offset"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<DynamicEntry&, DYNAMIC_TAGS>>(&Binary::get),
        "Return first binary's " RST_CLASS_REF(lief.ELF.DynamicEntry) " given its " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) "",
        "tag"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<Segment&, SEGMENT_TYPES>>(&Binary::get),
        "Return **first** binary's " RST_CLASS_REF(lief.ELF.Segment) " given its " RST_CLASS_REF(lief.ELF.SEGMENT_TYPES) "",
        "type"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<Note&, NOTE_TYPES>>(&Binary::get),
        "Return **first** binary's " RST_CLASS_REF(lief.ELF.Note) " given its " RST_CLASS_REF(lief.ELF.NOTE_TYPES) "",
        "type"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<no_const_func<Section&, ELF_SECTION_TYPES>>(&Binary::get),
        "Return **first** binary's " RST_CLASS_REF(lief.ELF.Section) " given its " RST_CLASS_REF(lief.ELF.ELF_SECTION_TYPES) "",
        "type"_a,
        py::return_value_policy::reference)

    .def("has",
        static_cast<bool (Binary::*)(DYNAMIC_TAGS) const>(&Binary::has),
        "Check if the " RST_CLASS_REF(lief.ELF.DynamicEntry) " associated with the given " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) " exists",
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
        "Check if a section with the given name exists in the binary",
        "section_name"_a)

    .def("get_section",
        static_cast<no_const_func<Section&, const std::string&>>(&Binary::get_section),
        "Return the " RST_CLASS_REF(lief.ELF.Section) " with the given ``name``",
        "section_name"_a,
        py::return_value_policy::reference)

    .def("add_static_symbol",
        &Binary::add_static_symbol,
        "Add a **static** " RST_CLASS_REF(lief.ELF.Symbol) " to the binary",
        "symbol"_a,
        py::return_value_policy::reference)

    .def("add_dynamic_symbol",
        static_cast<Symbol& (Binary::*)(const Symbol&, const SymbolVersion&)>(&Binary::add_dynamic_symbol),
        "Add a **dynamic** " RST_CLASS_REF(lief.ELF.Symbol) " to the binary",
        "symbol"_a, "symbol_version"_a = SymbolVersion::local(),
        py::return_value_policy::reference)

    .def("virtual_address_to_offset",
        &Binary::virtual_address_to_offset,
        "Convert the virtual address to an offset in the binary",
        "virtual_address"_a)

    .def("add",
        static_cast<Section& (Binary::*)(const Section&, bool)>(&Binary::add),
        "Add the given " RST_CLASS_REF(lief.ELF.Section) " to the binary. \n\n"
        "If the section should not be loaded in memory, ``loaded`` parameter have to be set to ``False`` (default: ``True``)",
        "section"_a, "loaded"_a = true,
        py::return_value_policy::reference)

    .def("add",
        static_cast<Segment& (Binary::*)(const Segment&, uint64_t)>(&Binary::add),
        "Add a segment in the binary",
        "segment"_a, "base"_a = 0,
        py::return_value_policy::reference)

    .def("add",
        static_cast<Note& (Binary::*)(const Note&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.ELF.Note) " in the binary",
        "note"_a,
        py::return_value_policy::reference)

    .def("replace",
        static_cast<Segment& (Binary::*)(const Segment&, const Segment&, uint64_t)>(&Binary::replace),
        "Replace the segment given in 2nd parameter with the segment given in the first one and return the updated segment",
        "new_segment"_a, "original_segment"_a, "base"_a = 0,
        py::return_value_policy::reference)

    .def("extend",
        static_cast<Segment& (Binary::*)(const Segment&, uint64_t)>(&Binary::extend),
        "Extend the given given " RST_CLASS_REF(lief.ELF.Segment) " by the given size",
        "segment"_a, "size"_a,
        py::return_value_policy::reference)

    .def("extend",
        static_cast<Section& (Binary::*)(const Section&, uint64_t)>(&Binary::extend),
        "Extend the given given " RST_CLASS_REF(lief.ELF.Section) " by the given size",
        "segment"_a, "size"_a,
        py::return_value_policy::reference)

    .def("remove",
        static_cast<void (Binary::*)(const DynamicEntry&)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.DynamicEntry) " from the dynamic table",
        "dynamic_entry"_a)

    .def("remove",
        static_cast<void (Binary::*)(DYNAMIC_TAGS)>(&Binary::remove),
        "Remove **all** " RST_CLASS_REF(lief.ELF.DynamicEntry) " with the given " RST_CLASS_REF(lief.ELF.DYNAMIC_TAGS) "",
        "tag"_a)

    .def("remove",
        static_cast<void (Binary::*)(const Section&, bool)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.Section) ". ``clear`` specify whether or not "
        "we must fill its content with ``0`` before removing",
        "section"_a, "clear"_a = false)

    .def("remove",
        static_cast<void (Binary::*)(const Note&)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.ELF.Note) "",
        "note"_a)

    .def("remove",
        static_cast<void (Binary::*)(NOTE_TYPES)>(&Binary::remove),
        "Remove **all** " RST_CLASS_REF(lief.ELF.Note) " with the given " RST_CLASS_REF(lief.ELF.NOTE_TYPES) "",
        "type"_a)

    .def_property_readonly("has_notes",
        &Binary::has_notes,
        "``True`` if the binary contains notes")

    .def_property_readonly("notes",
        static_cast<no_const_getter<it_notes>>(&Binary::notes),
        "Return an iterator to " RST_CLASS_REF(lief.ELF.Note) " entries as a list",
        py::return_value_policy::reference_internal)

    .def("strip",
        &Binary::strip,
        "Strip the binary")

    .def("permute_dynamic_symbols",
        &Binary::permute_dynamic_symbols,
        "Apply the given permutation on the dynamic symbols table",
        "permutation"_a)

    .def("write",
        &Binary::write,
        "Rebuild the binary and write it in a file",
        "output"_a,
        py::return_value_policy::reference_internal)

    .def_property_readonly("last_offset_section",
        &Binary::last_offset_section,
        "Return the last offset used in binary according to **section headers**")

    .def_property_readonly("last_offset_segment",
        &Binary::last_offset_segment,
        "Return the last offset used in binary according to **segment headers**")

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

    .def("remove_section",
        &Binary::remove_section,
        "Remove the given section from its name",
        "section_name"_a, "clear"_a = false)

    .def("get_library",
        static_cast<no_const_func<DynamicEntryLibrary&, const std::string&>>(&Binary::get_library),
        "Return the " RST_CLASS_REF(lief.ELF.DynamicEntryLibrary) " with the given ``name``",
        "library_name"_a,
        py::return_value_policy::reference)

    .def("has_dynamic_symbol",
        &Binary::has_dynamic_symbol,
        "Check if the symbol with the given ``name`` exists in the **dynamic** symbol table",
        "symbol_name"_a)

    .def("get_dynamic_symbol",
        static_cast<no_const_func<Symbol&, const std::string&>>(&Binary::get_dynamic_symbol),
        "Get the dynamic symbol from the given name",
        "symbol_name"_a,
        py::return_value_policy::reference)

    .def("has_static_symbol",
        &Binary::has_static_symbol,
        "Check if the symbol with the given ``name`` exists in the **static** symbol table",
        "symbol_name"_a)

    .def("get_static_symbol",
        static_cast<no_const_func<Symbol&, const std::string&>>(&Binary::get_static_symbol),
        "Get the **dynamic** symbol from the given ``name``",
        "symbol_name"_a,
        py::return_value_policy::reference)


    .def("add_exported_function",
        &Binary::add_exported_function,
        "Create a symbol for the function at the given ``address`` and export it",
        "address"_a, "name"_a = "",
        py::return_value_policy::reference)


    .def("export_symbol",
        static_cast<Symbol& (Binary::*)(const Symbol&)>(&Binary::export_symbol),
        "Export the given symbol and create it if it doesn't exist",
        "symbol"_a,
        py::return_value_policy::reference)


    .def("export_symbol",
        static_cast<Symbol& (Binary::*)(const std::string&, uint64_t)>(&Binary::export_symbol),
        "Export the symbol with the given name and create it if it doesn't exist",
        "symbol_name"_a, "value"_a = 0,
        py::return_value_policy::reference)



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
        static_cast<Segment& (Binary::*)(SEGMENT_TYPES)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__getitem__",
        static_cast<Note& (Binary::*)(NOTE_TYPES)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__getitem__",
        static_cast<DynamicEntry& (Binary::*)(DYNAMIC_TAGS)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)


    .def("__getitem__",
        static_cast<Section& (Binary::*)(ELF_SECTION_TYPES)>(&Binary::operator[]),
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
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          std::string str = stream.str();
          return str;
        });
}
