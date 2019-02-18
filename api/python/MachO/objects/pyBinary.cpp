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

#include "LIEF/MachO/hash.hpp"

#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using no_const_getter = T (Binary::*)(void);

template<class T, class P>
using no_const_func = T (Binary::*)(P);


template<>
void create<Binary>(py::module& m) {


  py::class_<Binary, LIEF::Binary>(m, "Binary")
    .def_property_readonly("header",
        static_cast<no_const_getter<Header&>>(&Binary::header),
        "Return binary's " RST_CLASS_REF(lief.MachO.Header) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&Binary::sections),
        "Return binary's " RST_CLASS_REF(lief.MachO.Section) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("relocations",
        static_cast<no_const_getter<it_relocations>>(&Binary::relocations),
        "Return an iterator over binary's " RST_CLASS_REF(lief.MachO.Relocation) "",
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

    .def("has_symbol",
        &Binary::has_symbol,
        "Check if a " RST_CLASS_REF(lief.MachO.Symbol) " with the given name exists",
        "name"_a)

    .def("get_symbol",
        static_cast<no_const_func<Symbol&, const std::string&>>(&Binary::get_symbol),
        "Return the " RST_CLASS_REF(lief.MachO.Symbol) " from the given name",
        "name"_a,
        py::return_value_policy::reference)

    .def_property_readonly("imported_symbols",
        static_cast<no_const_getter<it_imported_symbols>>(&Binary::imported_symbols),
        "Return binary's " RST_CLASS_REF(lief.MachO.Symbol) " which are imported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("exported_symbols",
        static_cast<no_const_getter<it_exported_symbols>>(&Binary::exported_symbols),
        "Return binary's " RST_CLASS_REF(lief.MachO.Symbol) " which are exported",
        py::return_value_policy::reference_internal)

    .def_property_readonly("commands",
        static_cast<no_const_getter<it_commands>>(&Binary::commands),
        "Return binary's " RST_CLASS_REF(lief.MachO.Command) "",
        py::return_value_policy::reference_internal)

    .def_property_readonly("imagebase",
        &Binary::imagebase,
        "Return binary's ``image base`` which is the base address\
        where segments are mapped (without PIE). ``0`` if not relevant.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("fat_offset",
        &Binary::fat_offset,
        "Return binary's *fat offset*. ``0`` if not relevant.",
        py::return_value_policy::copy)

    .def("section_from_offset",
        static_cast<Section* (Binary::*)(uint64_t)>(&Binary::section_from_offset),
        "Return the " RST_CLASS_REF(lief.MachO.Section) " which contains the offset",
        py::return_value_policy::reference)

    .def("section_from_virtual_address",
        static_cast<Section* (Binary::*)(uint64_t)>(&Binary::section_from_virtual_address),
        "Return the " RST_CLASS_REF(lief.MachO.Section) " which contains the virtual address",
        py::return_value_policy::reference)

    .def("segment_from_offset",
        static_cast<SegmentCommand* (Binary::*)(uint64_t)>(&Binary::segment_from_offset),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " which contains the offset",
        py::return_value_policy::reference)

    .def("segment_from_virtual_address",
        static_cast<SegmentCommand* (Binary::*)(uint64_t)>(&Binary::segment_from_virtual_address),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " which contains the virtual address",
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

    .def_property_readonly("has_version_min",
        &Binary::has_version_min,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.VersionMin) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("version_min",
        static_cast<no_const_getter<VersionMin&>>(&Binary::version_min),
        "Return binary's " RST_CLASS_REF(lief.MachO.VersionMin) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_thread_command",
        &Binary::has_thread_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.ThreadCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("thread_command",
        static_cast<no_const_getter<ThreadCommand&>>(&Binary::thread_command),
        "Return binary's " RST_CLASS_REF(lief.MachO.ThreadCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_rpath",
        &Binary::has_rpath,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.RPathCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("rpath",
        static_cast<no_const_getter<RPathCommand&>>(&Binary::rpath),
        "Return binary's " RST_CLASS_REF(lief.MachO.RPathCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_symbol_command",
        &Binary::has_symbol_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SymbolCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("symbol_command",
        static_cast<no_const_getter<SymbolCommand&>>(&Binary::symbol_command),
        "Return binary's " RST_CLASS_REF(lief.MachO.SymbolCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_dynamic_symbol_command",
        &Binary::has_dynamic_symbol_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DynamicSymbolCommand) " command.",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dynamic_symbol_command",
        static_cast<no_const_getter<DynamicSymbolCommand&>>(&Binary::dynamic_symbol_command),
        "Return binary's " RST_CLASS_REF(lief.MachO.DynamicSymbolCommand) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_code_signature",
        &Binary::has_code_signature,
        "``True`` if the binary is signed (i.e. has a " RST_CLASS_REF(lief.MachO.CodeSignature) " command)",
        py::return_value_policy::reference_internal)

    .def_property_readonly("code_signature",
        static_cast<no_const_getter<CodeSignature&>>(&Binary::code_signature),
        "Return binary's " RST_CLASS_REF(lief.MachO.CodeSignature) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_data_in_code",
        &Binary::has_data_in_code,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DataInCode) " command",
        py::return_value_policy::reference_internal)

    .def_property_readonly("data_in_code",
        static_cast<no_const_getter<DataInCode&>>(&Binary::data_in_code),
        "Return binary's " RST_CLASS_REF(lief.MachO.DataInCode) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_segment_split_info",
        &Binary::has_segment_split_info,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SegmentSplitInfo) " command",
        py::return_value_policy::reference_internal)

    .def_property_readonly("segment_split_info",
        static_cast<no_const_getter<SegmentSplitInfo&>>(&Binary::segment_split_info),
        "Return binary's " RST_CLASS_REF(lief.MachO.SegmentSplitInfo) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_sub_framework",
        &Binary::has_sub_framework,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SubFramework) " command",
        py::return_value_policy::reference_internal)

    .def_property_readonly("sub_framework",
        static_cast<no_const_getter<SubFramework&>>(&Binary::sub_framework),
        "Return binary's " RST_CLASS_REF(lief.MachO.SubFramework) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_dyld_environment",
        &Binary::has_dyld_environment,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DyldEnvironment) " command",
        py::return_value_policy::reference_internal)

    .def_property_readonly("dyld_environment",
        static_cast<no_const_getter<DyldEnvironment&>>(&Binary::dyld_environment),
        "Return binary's " RST_CLASS_REF(lief.MachO.DyldEnvironment) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_encryption_info",
        &Binary::has_encryption_info,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.EncryptionInfo) " command",
        py::return_value_policy::reference_internal)

    .def_property_readonly("encryption_info",
        static_cast<no_const_getter<EncryptionInfo&>>(&Binary::encryption_info),
        "Return binary's " RST_CLASS_REF(lief.MachO.EncryptionInfo) " if any.",
        py::return_value_policy::reference)

    .def_property_readonly("has_build_version",
        &Binary::has_build_version,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.BuildVersion) " command",
        py::return_value_policy::reference_internal)

    .def_property_readonly("build_version",
        static_cast<no_const_getter<BuildVersion&>>(&Binary::build_version),
        "Return binary's " RST_CLASS_REF(lief.MachO.BuildVersion) " if any.",
        py::return_value_policy::reference)


    .def("virtual_address_to_offset",
        &Binary::virtual_address_to_offset,
        "Convert the virtual address to an offset in the binary",
        "virtual_address"_a)

    .def("has_section",
        &Binary::has_section,
        "Check if a section with the given name exists",
        "name"_a)

    .def("get_section",
        static_cast<Section& (Binary::*)(const std::string&)>(&Binary::get_section),
        "Return the section from the given name",
        "name"_a,
        py::return_value_policy::reference)

    .def("has_segment",
        &Binary::has_segment,
        "Check if a " RST_CLASS_REF(lief.MachO.SegmentCommand) "  with the given name exists",
        "name"_a)

    .def("get_segment",
        static_cast<SegmentCommand* (Binary::*)(const std::string&)>(&Binary::get_segment),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " from the given name",
        "name"_a,
        py::return_value_policy::reference)

    .def_property_readonly("va_ranges",
        &Binary::va_ranges,
        "Return the range of virtual addresses as a tuple ``(va_start, va_end)``")

    .def_property_readonly("off_ranges",
        &Binary::off_ranges,
        "Return the range of offsets as a tuple ``(off_start, off_end)``")

    .def("is_valid_addr",
        &Binary::is_valid_addr,
        "Check if the given address is comprise between the lowest "
        "virtual address and the biggest one",
        "address"_a)

    .def("write",
        &Binary::write,
        "Rebuild the binary and write it in a file",
        "output"_a,
        py::return_value_policy::reference_internal)

    .def("add",
        static_cast<LoadCommand& (Binary::*)(const DylibCommand&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.DylibCommand) "",
        "dylib_command"_a,
        py::return_value_policy::reference)

    .def("add",
        static_cast<LoadCommand& (Binary::*)(const SegmentCommand&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.SegmentCommand) "",
        "segment"_a,
        py::return_value_policy::reference)

    .def("add",
        static_cast<LoadCommand& (Binary::*)(const LoadCommand&)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.LoadCommand) "",
        "load_command"_a,
        py::return_value_policy::reference)

    .def("add",
        static_cast<LoadCommand& (Binary::*)(const LoadCommand&, size_t)>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.LoadCommand) " at ``index``",
        "load_command"_a, "index"_a,
        py::return_value_policy::reference)


    .def("remove",
        static_cast<bool (Binary::*)(const LoadCommand&)>(&Binary::remove),
        "Remove a " RST_CLASS_REF(lief.MachO.LoadCommand) "",
        "load_command"_a)

    .def("remove",
        static_cast<bool (Binary::*)(LOAD_COMMAND_TYPES)>(&Binary::remove),
        "Remove **all** " RST_CLASS_REF(lief.MachO.LoadCommand) " having the given "
        "" RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES) "",
        "type"_a)

    .def("remove",
        static_cast<bool (Binary::*)(const Symbol&)>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.Symbol)"",
        "symbol"_a)

    .def("remove_command",
        static_cast<bool (Binary::*)(size_t)>(&Binary::remove_command),
        "Remove the " RST_CLASS_REF(lief.MachO.LoadCommand) " at ``index``",
        "index"_a)

    .def("remove_signature",
        static_cast<bool (Binary::*)(void)>(&Binary::remove_signature),
        "Remove the " RST_CLASS_REF(lief.MachO.CodeSignature) " (if any)")

    .def("remove_symbol",
        static_cast<bool (Binary::*)(const std::string&)>(&Binary::remove_symbol),
        "Remove all symbol(s) with the given name",
        "name"_a)

    .def("can_remove",
        static_cast<bool (Binary::*)(const Symbol&) const>(&Binary::can_remove),
        "Check if the given symbol can be safely removed.",
        "symbol"_a)

    .def("can_remove_symbol",
        static_cast<bool (Binary::*)(const std::string&) const>(&Binary::can_remove_symbol),
        "Check if the given symbol name can be safely removed.",
        "symbol_name"_a)

    .def("unexport",
        static_cast<bool (Binary::*)(const std::string&)>(&Binary::unexport),
        "Remove the symbol from the export table",
        "name"_a)

    .def("unexport",
        static_cast<bool (Binary::*)(const Symbol&)>(&Binary::unexport),
        "Remove the symbol from the export table",
        "symbol"_a)

    .def("extend",
        static_cast<bool (Binary::*)(const LoadCommand&, uint64_t)>(&Binary::extend),
        "Extend a " RST_CLASS_REF(lief.MachO.LoadCommand) " by ``size``",
        "load_command"_a, "size"_a)

    .def("extend_segment",
        static_cast<bool (Binary::*)(const SegmentCommand&, size_t)>(&Binary::extend_segment),
        "Extend the **content** of the given " RST_CLASS_REF(lief.MachO.SegmentCommand) " by ``size``",
        "segment_command"_a, "size"_a)

    .def("add_section",
        static_cast<Section* (Binary::*)(const SegmentCommand&, const Section&)>(&Binary::add_section),
        "Add a new " RST_CLASS_REF(lief.MachO.Section) " in the given " RST_CLASS_REF(lief.MachO.SegmentCommand) "",
        "segment"_a, "section"_a,
        py::return_value_policy::reference)

    .def("add_section",
        static_cast<Section* (Binary::*)(const Section&)>(&Binary::add_section),
        "Add a new " RST_CLASS_REF(lief.MachO.Section) " within the ``__TEXT`` segment",
        "section"_a,
        py::return_value_policy::reference)


    .def("add_section",
        static_cast<Section* (Binary::*)(const SegmentCommand&, const Section&)>(&Binary::add_section),
        "Add a new " RST_CLASS_REF(lief.MachO.Section) " in the given " RST_CLASS_REF(lief.MachO.SegmentCommand) "",
        "section"_a, "section"_a,
        py::return_value_policy::reference)

    .def("add_library",
        static_cast<LoadCommand& (Binary::*)(const std::string&)>(&Binary::add_library),
        "Add a new library dependency",
        "library_name"_a,
        py::return_value_policy::reference)

    .def("get",
        static_cast<LoadCommand& (Binary::*)(LOAD_COMMAND_TYPES)>(&Binary::get),
        "Return the **first** " RST_CLASS_REF(lief.MachO.LoadCommand) " having the given "
        "" RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES) "",
        "type"_a,
        py::return_value_policy::reference)

    .def("has",
        static_cast<bool(Binary::*)(LOAD_COMMAND_TYPES) const>(&Binary::has),
        "Check if the current binary has a " RST_CLASS_REF(lief.MachO.LoadCommand) " with the given "
        "" RST_CLASS_REF(lief.MachO.LOAD_COMMAND_TYPES) "",
        "type"_a)

    .def_property_readonly("unwind_functions",
        &Binary::unwind_functions,
        "Return list of " RST_CLASS_REF(lief.Function) " found in the ``__unwind_info`` section")

    .def_property_readonly("functions",
        &Binary::functions,
        "Return list of **all** " RST_CLASS_REF(lief.Function) " found")

    .def("__getitem__",
        static_cast<LoadCommand& (Binary::*)(LOAD_COMMAND_TYPES)>(&Binary::operator[]),
        "",
        py::return_value_policy::reference)

    .def("__contains__",
        static_cast<bool(Binary::*)(LOAD_COMMAND_TYPES) const>(&Binary::has))


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

