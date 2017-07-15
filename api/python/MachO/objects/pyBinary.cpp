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

#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/MachO/Binary.hpp"

#include "pyMachO.hpp"

template<class T>
using no_const_getter = T (Binary::*)(void);

void init_MachO_Binary_class(py::module& m) {


  py::class_<Binary, LIEF::Binary>(m, "Binary")
    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&Binary::header),
        "Return binary's " RST_CLASS_REF(lief.MachO.Header) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&Binary::sections),
        "Return binary's " RST_CLASS_REF(lief.MachO.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("segments",
        static_cast<no_const_getter<it_segments>>(&Binary::segments),
        "Return binary's " RST_CLASS_REF(lief.MachO.SegmentCommand) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("libraries",
        static_cast<no_const_getter<it_libraries>>(&Binary::libraries),
        "Return binary's " RST_CLASS_REF(lief.MachO.DylibCommand) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbols",
        static_cast<no_const_getter<it_symbols>>(&Binary::symbols),
        "Return binary's " RST_CLASS_REF(lief.MachO.Symbol) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("imported_symbols",
        static_cast<no_const_getter<it_imported_symbols>>(&Binary::get_imported_symbols),
        "Return binary's " RST_CLASS_REF(lief.MachO.Symbol) " which are imported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_symbols",
        static_cast<no_const_getter<it_exported_symbols>>(&Binary::get_exported_symbols),
        "Return binary's " RST_CLASS_REF(lief.MachO.Symbol) " which are exported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("commands",
        static_cast<no_const_getter<it_commands>>(&Binary::commands),
        "Return binary's " RST_CLASS_REF(lief.MachO.Command) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("imagebase",
        &Binary::imagebase,
        "Return binary's ``image base`` which is the base address\
        where segments are mapped (without PIE)",
        py::return_value_policy::reference_internal)

    .def_property_readonly("fat_offset",
        &Binary::fat_offset,
        "Return binary's ``fat_offset``. 0 if not relevant.",
        py::return_value_policy::copy)

    .def("section_from_offset",
        static_cast<Section& (Binary::*)(uint64_t)>(&Binary::section_from_offset),
        "Return the " RST_CLASS_REF(lief.MachO.Section) " which contains the offset",
        py::return_value_policy::reference)

    .def("segment_from_offset",
        static_cast<SegmentCommand& (Binary::*)(uint64_t)>(&Binary::segment_from_offset),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " which contains the offset",
        py::return_value_policy::reference)

    .def("segment_from_virtual_address",
        static_cast<SegmentCommand& (Binary::*)(uint64_t)>(&Binary::segment_from_virtual_address),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " which contains the (relative) virtual address",
        py::return_value_policy::reference)

    .def_property_readonly("has_entrypoint",
        &Binary::has_entrypoint,
        "``True`` if the binary has an entrypoint.\n"
        "Basically for libraries it will return ``false``",
        py::return_value_policy::reference_internal)

    .def_property_readonly("has_uuid",
        &Binary::has_uuid,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.UUIDCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("uuid",
        static_cast<no_const_getter<UUIDCommand&>>(&Binary::uuid),
        "Return binary's " RST_CLASS_REF(lief.MachO.UUIDCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_main_command",
        &Binary::has_main_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.MainCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("main_command",
        static_cast<no_const_getter<MainCommand&>>(&Binary::main_command),
        "Return binary's " RST_CLASS_REF(lief.MachO.MainCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_dylinker",
        &Binary::has_dylinker,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DylinkerCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dylinker",
        static_cast<no_const_getter<DylinkerCommand&>>(&Binary::dylinker),
        "Return binary's " RST_CLASS_REF(lief.MachO.DylinkerCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_dyld_info",
        &Binary::has_dyld_info,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DyldInfo) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dyld_info",
        static_cast<no_const_getter<DyldInfo&>>(&Binary::dyld_info),
        "Return binary's " RST_CLASS_REF(lief.MachO.DyldInfo) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_function_starts",
        &Binary::has_function_starts,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.FunctionStarts) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("function_starts",
        static_cast<no_const_getter<FunctionStarts&>>(&Binary::function_starts),
        "Return binary's " RST_CLASS_REF(lief.MachO.FunctionStarts) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_source_version",
        &Binary::has_source_version,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SourceVersion) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("source_version",
        static_cast<no_const_getter<SourceVersion&>>(&Binary::source_version),
        "Return binary's " RST_CLASS_REF(lief.MachO.SourceVersion) " if any.",
        py::return_value_policy::reference)

    .def("virtual_address_to_offset",
        &Binary::virtual_address_to_offset,
        "Convert the virtual address to an offset in the binary",
        "virtual_address"_a)


    .def("__str__",
        [] (const Binary& binary)
        {
          std::ostringstream stream;
          stream << binary;
          std::string str = stream.str();
          return str;
        });

}

