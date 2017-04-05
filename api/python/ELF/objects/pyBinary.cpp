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
#include "LIEF/Abstract/Binary.hpp"

#include "pyELF.hpp"

template<class T>
using no_const_getter = T (Binary::*)(void);

template<class T, class P>
using no_const_func = T (Binary::*)(P);

void init_ELF_Binary_class(py::module& m) {

  // Binary object
  py::class_<Binary, LIEF::Binary>(m, "Binary", "ELF binary representation")
    .def(py::init<const std::string &, ELF_CLASS>())

    .def_property_readonly("type",
        &Binary::type)

    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&Binary::get_header),
        "Return " RST_CLASS_REF(lief.ELF.Header) " object",
        py::return_value_policy::reference_internal)

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&Binary::get_sections),
        "Return binary's " RST_CLASS_REF(lief.ELF.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("segments",
        static_cast<no_const_getter<it_segments>>(&Binary::get_segments),
        "Return binary's " RST_CLASS_REF(lief.ELF.Segment) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_entries",
        static_cast<no_const_getter<it_dynamic_entries>>(&Binary::get_dynamic_entries),
        "Return " RST_CLASS_REF(lief.ELF.DynamicEntry) " entries as a list",
        py::return_value_policy::reference_internal)

    .def_property_readonly("static_symbols",
        static_cast<no_const_getter<it_symbols>>(&Binary::get_static_symbols),
        "Return static's " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_symbols",
        static_cast<no_const_getter<it_symbols>>(&Binary::get_dynamic_symbols),
        "Return dynamic's " RST_CLASS_REF(lief.ELF.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_symbols",
        static_cast<no_const_getter<it_exported_symbols>>(&Binary::get_exported_symbols),
        "Return dynamic's " RST_CLASS_REF(lief.ELF.Symbol) " which are exported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("imported_symbols",
        static_cast<no_const_getter<it_imported_symbols>>(&Binary::get_imported_symbols),
        "Return dynamic's " RST_CLASS_REF(lief.ELF.Symbol) " which are imported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_relocations",
        static_cast<no_const_getter<it_relocations>>(&Binary::get_dynamic_relocations),
        "Return PLT/GOT " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("pltgot_relocations",
        static_cast<no_const_getter<it_relocations>>(&Binary::get_pltgot_relocations),
        "Return dynamics " RST_CLASS_REF(lief.ELF.Relocation) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version",
        static_cast<no_const_getter<it_symbols_version>>(&Binary::get_symbols_version),
        "Return " RST_CLASS_REF(lief.ELF.SymbolVersion) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version_requirement",
        static_cast<no_const_getter<it_symbols_version_requirement>>(&Binary::get_symbols_version_requirement),
        "Return " RST_CLASS_REF(lief.ELF.SymbolVersionRequirement) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols_version_definition",
        static_cast<no_const_getter<it_symbols_version_definition>>(&Binary::get_symbols_version_definition),
        "Return " RST_CLASS_REF(lief.ELF.SymbolVersionDefinition) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("gnu_hash",
        &Binary::get_gnu_hash,
        "Return " RST_CLASS_REF(lief.ELF.GnuHash) " object",
        py::return_value_policy::reference_internal)

   .def_property_readonly("imagebase",
        &Binary::get_imagebase,
       "Return the program image base. (e.g. 0x400000)")

   .def_property_readonly("virtual_size",
        &Binary::get_virtual_size,
       "Return the binary's size when mapped in memory")

   .def_property_readonly("is_pie",
        &Binary::is_pie,
       "Check if the binary is a ``pie`` one")

   .def_property_readonly("has_interpreter",
        &Binary::has_interpreter,
       "Check if the binary uses a loader")

   .def_property_readonly("interpreter",
        &Binary::get_interpreter,
       "Return ELF interprer if any. (e.g. ``/lib64/ld-linux-x86-64.so.2``)")

    .def("section_from_offset",
        static_cast<no_const_func<Section&, uint64_t>>(&Binary::section_from_offset),
        "Return binary's " RST_CLASS_REF(lief.ELF.Section) " which holds the offset",
        "address"_a,
        py::return_value_policy::reference)

    .def("section_from_virtual_address",
        static_cast<no_const_func<Section&, uint64_t>>(&Binary::section_from_virtual_address),
        "Return binary's " RST_CLASS_REF(lief.ELF.Section) " which holds the given virtual address",
        py::return_value_policy::reference)

    .def("segment_from_virtual_address",
        static_cast<no_const_func<Segment&, uint64_t>>(&Binary::segment_from_virtual_address),
        "Return binary's " RST_CLASS_REF(lief.ELF.Segment) " which holds the address",
        py::return_value_policy::reference)

    .def("segment_from_offset",
        static_cast<no_const_func<Segment&, uint64_t>>(&Binary::segment_from_offset),
        "Return binary's " RST_CLASS_REF(lief.ELF.Segment) " which holds the offset",
        py::return_value_policy::reference)

    .def("dynamic_entry_from_tag",
        static_cast<no_const_func<DynamicEntry&, DYNAMIC_TAGS>>(&Binary::dynamic_entry_from_tag),
        "Return first binary's " RST_CLASS_REF(lief.ELF.DynamicEntry) " given its tag",
        py::return_value_policy::reference)

    .def("has_dynamic_entry",
        &Binary::has_dynamic_entry,
        "Check if the " RST_CLASS_REF(lief.ELF.DynamicEntry) " associated with the given tag exists")

    .def("patch_pltgot",
        static_cast<void (Binary::*) (const std::string&, uint64_t)>(&Binary::patch_pltgot),
        "Patch the imported symbol's name with the ``address``")

    .def("patch_pltgot",
        static_cast<void (Binary::*) (const Symbol&, uint64_t)>(&Binary::patch_pltgot),
        "Patch the imported symbol's name with the ``address``")

    .def("has_section",
        &Binary::has_section,
        "Check if a section with the given name exists in the binary")

    .def("get_section",
        static_cast<no_const_func<Section&, const std::string&>>(&Binary::get_section),
        py::return_value_policy::reference)

    .def("add_static_symbol",
        &Binary::add_static_symbol,
        py::return_value_policy::reference)

    .def("virtual_address_to_offset",
        &Binary::virtual_address_to_offset,
        "Convert the virtual address to an offset in the binary")

    .def("add_section",
        &Binary::add_section,
        "Add a section in the binary",
        py::return_value_policy::reference)

    .def("add_segment",
        &Binary::add_segment,
        "Add a segment in the binary",
        py::arg("segment"), py::arg_v("base", 0x400000), py::arg_v("force_note", false),
        py::return_value_policy::reference)

    .def("insert_content",
        &Binary::insert_content,
        "Add some data in the binary")

    .def("strip",
        &Binary::strip,
        "Strip the binary")

    .def("permute_dynamic_symbols",
        &Binary::permute_dynamic_symbols,
        "Apply the given permutation on the dynamic symbols table")

    .def("write",
        &Binary::write,
        "Rebuild the binary and write it in a file",
        py::return_value_policy::reference_internal)


    .def("__str__",
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          std::string str = stream.str();
          return str;
        });
}
