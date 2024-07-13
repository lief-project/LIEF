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
#include <string>
#include <sstream>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include "nanobind/extra/memoryview.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/BuildVersion.hpp"
#include "LIEF/MachO/Builder.hpp"
#include "LIEF/MachO/ChainedBindingInfo.hpp"
#include "LIEF/MachO/CodeSignature.hpp"
#include "LIEF/MachO/CodeSignatureDir.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/DyldBindingInfo.hpp"
#include "LIEF/MachO/DyldChainedFixups.hpp"
#include "LIEF/MachO/DyldEnvironment.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/DylinkerCommand.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/EncryptionInfo.hpp"
#include "LIEF/MachO/ExportInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/LinkEdit.hpp"
#include "LIEF/MachO/LinkerOptHint.hpp"
#include "LIEF/MachO/MainCommand.hpp"
#include "LIEF/MachO/RPathCommand.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/RelocationFixup.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/SourceVersion.hpp"
#include "LIEF/MachO/SubFramework.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/ThreadCommand.hpp"
#include "LIEF/MachO/TwoLevelHints.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/MachO/VersionMin.hpp"

#include "LIEF/ObjC/Metadata.hpp"

#include "pyErr.hpp"
#include "MachO/pyMachO.hpp"
#include "pyIterator.hpp"

namespace LIEF::MachO::py {

template<>
void create<Binary>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Binary, LIEF::Binary> bin(m, "Binary",
      R"delim(
      Class which represents a MachO binary
      )delim"_doc);

  init_ref_iterator<Binary::it_commands>(bin, "it_commands");

  init_ref_iterator<Binary::it_symbols>(bin, "it_symbols");
  init_ref_iterator<Binary::it_exported_symbols>(bin, "it_filter_symbols");
  init_ref_iterator<Binary::it_sections>(bin, "it_sections");
  init_ref_iterator<Binary::it_segments>(bin, "it_segments");
  init_ref_iterator<Binary::it_libraries>(bin, "it_libraries");
  init_ref_iterator<Binary::it_relocations>(bin, "it_relocations");
  init_ref_iterator<Binary::it_rpaths>(bin, "it_rpaths");

  nb::class_<Binary::range_t>(bin, "range_t")
    .def_rw("start", &Binary::range_t::start)
    .def_rw("end",   &Binary::range_t::end);

  // --> Already registered with FatMachO (same container)
  //init_ref_iterator<Binary::it_fileset_binaries>(bin, "it_fileset_binaries");

  bin
    .def_prop_ro("header",
        nb::overload_cast<>(&Binary::header),
        "Return binary's " RST_CLASS_REF(lief.MachO.Header) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("sections",
        nb::overload_cast<>(&Binary::sections),
        "Return an iterator over the binary's " RST_CLASS_REF(lief.MachO.Section) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("relocations",
        nb::overload_cast<>(&Binary::relocations),
        "Return an iterator over binary's " RST_CLASS_REF(lief.MachO.Relocation) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("segments",
        nb::overload_cast<>(&Binary::segments),
        "Return an iterator over the binary's " RST_CLASS_REF(lief.MachO.SegmentCommand) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("libraries",
        nb::overload_cast<>(&Binary::libraries),
        "Return an iterator over the binary's " RST_CLASS_REF(lief.MachO.DylibCommand) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("symbols",
        nb::overload_cast<>(&Binary::symbols),
        "Return an iterator over the binary's " RST_CLASS_REF(lief.MachO.Symbol) ""_doc,
        nb::keep_alive<0, 1>())

    .def("has_symbol",
        &Binary::has_symbol,
        "Check if a " RST_CLASS_REF(lief.MachO.Symbol) " with the given name exists"_doc,
        "name"_a)

    .def("get_symbol",
        nb::overload_cast<const std::string&>(&Binary::get_symbol),
        "Return the " RST_CLASS_REF(lief.MachO.Symbol) " from the given name"_doc,
        "name"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("imported_symbols",
        nb::overload_cast<>(&Binary::imported_symbols),
        "Return the binary's " RST_CLASS_REF(lief.MachO.Symbol) " which are imported"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("exported_symbols",
        nb::overload_cast<>(&Binary::exported_symbols),
        "Return the binary's " RST_CLASS_REF(lief.MachO.Symbol) " which are exported"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("commands",
        nb::overload_cast<>(&Binary::commands),
        "Return an iterator over the binary's " RST_CLASS_REF(lief.MachO.Command) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("filesets",
        nb::overload_cast<>(&Binary::filesets),
        "Return binary's " RST_CLASS_REF(lief.MachO.Filesets) ""_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_filesets",
        &Binary::has_filesets,
        "Return ``True`` if the binary has filesets"_doc)

    .def_prop_ro("fileset_name",
        &Binary::fileset_name,
        "Name associated with the LC_FILESET_ENTRY binary"_doc)

    .def_prop_ro("imagebase",
        &Binary::imagebase,
        R"delim(
        Return the binary's ``imagebase`` which is the base address
        where segments are mapped (without the ASLR). ``0`` if not relevant.
        )delim"_doc)

    .def_prop_ro("virtual_size",
        &Binary::virtual_size,
        "Binary's memory size when mapped"_doc)

    .def_prop_ro("fat_offset",
        &Binary::fat_offset,
        "Return binary's *fat offset*. ``0`` if not relevant."_doc,
        nb::rv_policy::copy)

    .def("section_from_offset",
        nb::overload_cast<uint64_t>(&Binary::section_from_offset),
        "Return the " RST_CLASS_REF(lief.MachO.Section) " which encompasses the offset"_doc,
        nb::rv_policy::reference_internal)

    .def("section_from_virtual_address",
        nb::overload_cast<uint64_t>(&Binary::section_from_virtual_address),
        "Return the " RST_CLASS_REF(lief.MachO.Section) " which encompasses the virtual address"_doc,
        nb::rv_policy::reference_internal)

    .def("segment_from_offset",
        nb::overload_cast<uint64_t>(&Binary::segment_from_offset),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " which encompasses the offset"_doc,
        nb::rv_policy::reference_internal)

    .def("segment_from_virtual_address",
        nb::overload_cast<uint64_t>(&Binary::segment_from_virtual_address),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " which encompasses the virtual address"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_entrypoint",
        &Binary::has_entrypoint,
        R"delim(
        ``True`` if the binary has an entrypoint.

        Basically for libraries it will return ``false``
        )delim"_doc)

    .def_prop_ro("has_uuid",
        &Binary::has_uuid,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.UUIDCommand) " command."_doc)

    .def_prop_ro("uuid",
        nb::overload_cast<>(&Binary::uuid),
        "Return the binary's " RST_CLASS_REF(lief.MachO.UUIDCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_main_command",
        &Binary::has_main_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.MainCommand) " command."_doc)

    .def_prop_ro("main_command",
        nb::overload_cast<>(&Binary::main_command),
        "Return the binary's " RST_CLASS_REF(lief.MachO.MainCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dylinker",
        &Binary::has_dylinker,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DylinkerCommand) " command."_doc)

    .def_prop_ro("dylinker",
        nb::overload_cast<>(&Binary::dylinker),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DylinkerCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dyld_info",
        &Binary::has_dyld_info,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DyldInfo) " command."_doc)

    .def_prop_ro("dyld_info",
        nb::overload_cast<>(&Binary::dyld_info),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DyldInfo) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_function_starts",
        &Binary::has_function_starts,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.FunctionStarts) " command."_doc)

    .def_prop_ro("function_starts",
        nb::overload_cast<>(&Binary::function_starts),
        "Return the binary's " RST_CLASS_REF(lief.MachO.FunctionStarts) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_source_version",
        &Binary::has_source_version,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SourceVersion) " command."_doc)

    .def_prop_ro("source_version",
        nb::overload_cast<>(&Binary::source_version),
        "Return the binary's " RST_CLASS_REF(lief.MachO.SourceVersion) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_version_min",
        &Binary::has_version_min,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.VersionMin) " command."_doc)

    .def_prop_ro("version_min",
        nb::overload_cast<>(&Binary::version_min),
        "Return the binary's " RST_CLASS_REF(lief.MachO.VersionMin) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_thread_command",
        &Binary::has_thread_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.ThreadCommand) " command."_doc)

    .def_prop_ro("thread_command",
        nb::overload_cast<>(&Binary::thread_command),
        "Return the binary's " RST_CLASS_REF(lief.MachO.ThreadCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_rpath",
        &Binary::has_rpath,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.RPathCommand) " command."_doc)

    .def_prop_ro("rpath",
        nb::overload_cast<>(&Binary::rpath),
        "Return the binary's " RST_CLASS_REF(lief.MachO.RPathCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("rpaths",
        nb::overload_cast<>(&Binary::rpaths),
        "Return an iterator over the binary's " RST_CLASS_REF(lief.MachO.RPathCommand) ""_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("has_symbol_command",
        &Binary::has_symbol_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SymbolCommand) " command."_doc)

    .def_prop_ro("symbol_command",
        nb::overload_cast<>(&Binary::symbol_command),
        "Return the binary's " RST_CLASS_REF(lief.MachO.SymbolCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dynamic_symbol_command",
        &Binary::has_dynamic_symbol_command,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DynamicSymbolCommand) " command."_doc)

    .def_prop_ro("dynamic_symbol_command",
        nb::overload_cast<>(&Binary::dynamic_symbol_command),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DynamicSymbolCommand) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_code_signature",
        &Binary::has_code_signature,
        "``True`` if the binary is signed (i.e. has a " RST_CLASS_REF(lief.MachO.CodeSignature) " command)"_doc)

    .def_prop_ro("code_signature",
        nb::overload_cast<>(&Binary::code_signature),
        "Return the binary's " RST_CLASS_REF(lief.MachO.CodeSignature) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_code_signature_dir",
        &Binary::has_code_signature_dir,
        "``True`` if the binary is signed (i.e. has a " RST_CLASS_REF(lief.MachO.CodeSignatureDir) " command) "
        "with the command LC_DYLIB_CODE_SIGN_DRS"_doc)

    .def_prop_ro("code_signature_dir",
        nb::overload_cast<>(&Binary::code_signature_dir),
        "Return the binary's " RST_CLASS_REF(lief.MachO.CodeSignatureDir) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_data_in_code",
        &Binary::has_data_in_code,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DataInCode) " command"_doc)

    .def_prop_ro("data_in_code",
        nb::overload_cast<>(&Binary::data_in_code),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DataInCode) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_segment_split_info",
        &Binary::has_segment_split_info,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SegmentSplitInfo) " command"_doc)

    .def_prop_ro("segment_split_info",
        nb::overload_cast<>(&Binary::segment_split_info),
        "Return the binary's " RST_CLASS_REF(lief.MachO.SegmentSplitInfo) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_sub_framework",
        &Binary::has_sub_framework,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.SubFramework) " command"_doc)

    .def_prop_ro("sub_framework",
        nb::overload_cast<>(&Binary::sub_framework),
        "Return the binary's " RST_CLASS_REF(lief.MachO.SubFramework) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dyld_environment",
        &Binary::has_dyld_environment,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DyldEnvironment) " command"_doc)

    .def_prop_ro("dyld_environment",
        nb::overload_cast<>(&Binary::dyld_environment),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DyldEnvironment) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_encryption_info",
        &Binary::has_encryption_info,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.EncryptionInfo) " command"_doc)

    .def_prop_ro("encryption_info",
        nb::overload_cast<>(&Binary::encryption_info),
        "Return the binary's " RST_CLASS_REF(lief.MachO.EncryptionInfo) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_build_version",
        &Binary::has_build_version,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.BuildVersion) " command"_doc)

    .def_prop_ro("build_version",
        nb::overload_cast<>(&Binary::build_version),
        "Return the binary's " RST_CLASS_REF(lief.MachO.BuildVersion) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dyld_chained_fixups",
        &Binary::has_dyld_chained_fixups,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DyldChainedFixups) " command"_doc)

    .def_prop_ro("dyld_chained_fixups",
        nb::overload_cast<>(&Binary::dyld_chained_fixups),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DyldChainedFixups) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_dyld_exports_trie",
        &Binary::has_dyld_exports_trie,
        "``True`` if the binary has a " RST_CLASS_REF(lief.MachO.DyldExportsTrie) " command"_doc)

    .def_prop_ro("dyld_exports_trie",
        nb::overload_cast<>(&Binary::dyld_exports_trie),
        "Return the binary's " RST_CLASS_REF(lief.MachO.DyldExportsTrie) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_two_level_hints",
        &Binary::has_two_level_hints,
        "``True`` if the binary embeds the Two Level Hint command (" RST_CLASS_REF(lief.MachO.TwoLevelHints) ")"_doc)

    .def_prop_ro("two_level_hints",
        nb::overload_cast<>(&Binary::two_level_hints),
        "Return the binary's " RST_CLASS_REF(lief.MachO.TwoLevelHints) " if any, or None"_doc,
        nb::rv_policy::reference_internal)


    .def_prop_ro("has_linker_opt_hint",
        &Binary::has_linker_opt_hint,
        "``True`` if the binary embeds the Linker optimization hint command (" RST_CLASS_REF(lief.MachO.LinkerOptHint) ")"_doc)

    .def_prop_ro("linker_opt_hint",
        nb::overload_cast<>(&Binary::linker_opt_hint),
        "Return the binary's " RST_CLASS_REF(lief.MachO.LinkerOptHint) " if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def("virtual_address_to_offset",
        [] (const Binary& self, uint64_t va) {
          return error_or(&Binary::virtual_address_to_offset, self, va);
        },
        "Convert the virtual address to an offset in the binary"_doc,
        "virtual_address"_a)

    .def("has_section",
        &Binary::has_section,
        "Check if a section with the given name exists"_doc,
        "name"_a)

    .def("get_section",
        nb::overload_cast<const std::string&>(&Binary::get_section),
        "Return the section from the given name or None if the section does not exist"_doc,
        "name"_a,
        nb::rv_policy::reference_internal)

    .def("has_segment",
        &Binary::has_segment,
        "Check if a " RST_CLASS_REF(lief.MachO.SegmentCommand) "  with the given name exists"_doc,
        "name"_a)

    .def("get_segment",
        nb::overload_cast<const std::string&>(&Binary::get_segment),
        "Return the " RST_CLASS_REF(lief.MachO.SegmentCommand) " from the given name"_doc,
        "name"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("va_ranges",
        &Binary::va_ranges,
        "Return the range of virtual addresses as a tuple ``(va_start, va_end)``"_doc)

    .def_prop_ro("off_ranges",
        &Binary::off_ranges,
        "Return the range of offsets as a tuple ``(off_start, off_end)``"_doc)

    .def("is_valid_addr",
        &Binary::is_valid_addr,
        R"delim(
        Check if the given address is encompassed between the range of virtual addresses.

        See: :attr:`~lief.MachO.Binary.va_ranges`
        )delim"_doc,
        "address"_a)

    .def("write",
        nb::overload_cast<const std::string&>(&Binary::write),
        "Rebuild the binary and write and write its content if the file given in parameter"_doc,
        "output"_a,
        nb::rv_policy::reference_internal)

    .def("add",
        nb::overload_cast<const DylibCommand&>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.DylibCommand) ""_doc,
        "dylib_command"_a,
        nb::rv_policy::reference_internal)

    .def("add",
        nb::overload_cast<const SegmentCommand&>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.SegmentCommand) ""_doc,
        "segment"_a,
        nb::rv_policy::reference_internal)

    .def("add",
        nb::overload_cast<const LoadCommand&>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.LoadCommand) ""_doc,
        "load_command"_a,
        nb::rv_policy::reference_internal)

    .def("add",
        nb::overload_cast<const LoadCommand&, size_t>(&Binary::add),
        "Add a new " RST_CLASS_REF(lief.MachO.LoadCommand) " at ``index``"_doc,
        "load_command"_a, "index"_a,
        nb::rv_policy::reference_internal)

    .def("remove",
        nb::overload_cast<const LoadCommand&>(&Binary::remove),
        "Remove a " RST_CLASS_REF(lief.MachO.LoadCommand) ""_doc,
        "load_command"_a)

    .def("remove",
        nb::overload_cast<LoadCommand::TYPE>(&Binary::remove),
        "Remove **all** the " RST_CLASS_REF(lief.MachO.LoadCommand) " with the given "
        "" RST_CLASS_REF(lief.MachO.LoadCommand.TYPE) ""_doc,
        "type"_a)

    .def("remove",
        nb::overload_cast<const Symbol&>(&Binary::remove),
        "Remove the given " RST_CLASS_REF(lief.MachO.Symbol)""_doc,
        "symbol"_a)

    .def("remove_command",
        nb::overload_cast<size_t>(&Binary::remove_command),
        "Remove the " RST_CLASS_REF(lief.MachO.LoadCommand) " at the given ``index``"_doc,
        "index"_a)

    .def("remove_section",
        nb::overload_cast<const std::string&, bool>(&Binary::remove_section),
        "Remove the section with the given name"_doc,
        "name"_a, "clear"_a = false)

    .def("remove_section",
        nb::overload_cast<const std::string&, const std::string&, bool>(&Binary::remove_section),
        R"delim(
        Remove the section from the segment with the name
        given in the first parameter and with the section's name provided in the
        second parameter.)delim"_doc,
        "segname"_a, "secname"_a, "clear"_a = false)

    .def("remove_signature",
        nb::overload_cast<>(&Binary::remove_signature),
        "Remove the " RST_CLASS_REF(lief.MachO.CodeSignature) " (if any)"_doc)

    .def("remove_symbol",
        nb::overload_cast<const std::string&>(&Binary::remove_symbol),
        "Remove all symbol(s) with the given name"_doc,
        "name"_a)

    .def("can_remove",
        nb::overload_cast<const Symbol&>(&Binary::can_remove, nb::const_),
        "Check if the given symbol can be safely removed."_doc,
        "symbol"_a)

    .def("can_remove_symbol",
        nb::overload_cast<const std::string&>(&Binary::can_remove_symbol, nb::const_),
        "Check if the given symbol name can be safely removed."_doc,
        "symbol_name"_a)

    .def("unexport",
        nb::overload_cast<const std::string&>(&Binary::unexport),
        "Remove the symbol from the export table"_doc,
        "name"_a)

    .def("unexport",
        nb::overload_cast<const Symbol&>(&Binary::unexport),
        "Remove the symbol from the export table"_doc,
        "symbol"_a)

    .def("extend",
        nb::overload_cast<const LoadCommand&, uint64_t>(&Binary::extend),
        "Extend a " RST_CLASS_REF(lief.MachO.LoadCommand) " by ``size``"_doc,
        "load_command"_a, "size"_a)

    .def("extend_segment",
        nb::overload_cast<const SegmentCommand&, size_t>(&Binary::extend_segment),
        "Extend the **content** of the given " RST_CLASS_REF(lief.MachO.SegmentCommand) " by ``size``"_doc,
        "segment_command"_a, "size"_a)

    .def("add_section",
        nb::overload_cast<const SegmentCommand&, const Section&>(&Binary::add_section),
        "Add a new " RST_CLASS_REF(lief.MachO.Section) " in the given " RST_CLASS_REF(lief.MachO.SegmentCommand) ""_doc,
        "segment"_a, "section"_a,
        nb::rv_policy::reference_internal)

    .def("add_section",
        nb::overload_cast<const Section&>(&Binary::add_section),
        "Add a new " RST_CLASS_REF(lief.MachO.Section) " within the ``__TEXT`` segment"_doc,
        "section"_a,
        nb::rv_policy::reference_internal)

    .def("add_library",
        nb::overload_cast<const std::string&>(&Binary::add_library),
        "Add a new library dependency"_doc,
        "library_name"_a,
        nb::rv_policy::reference_internal)

    .def("get",
        nb::overload_cast<LoadCommand::TYPE>(&Binary::get),
        "Return the **first** " RST_CLASS_REF(lief.MachO.LoadCommand) " with the given "
        "" RST_CLASS_REF(lief.MachO.LoadCommand.TYPE) " or None if it is not present."_doc,
        "type"_a, nb::rv_policy::reference_internal)

    .def("has",
        nb::overload_cast<LoadCommand::TYPE>(&Binary::has, nb::const_),
        "Check if the current binary has a " RST_CLASS_REF(lief.MachO.LoadCommand) " with the given "
        "" RST_CLASS_REF(lief.MachO.LoadCommand.TYPE) ""_doc,
        "type"_a)

    .def_prop_ro("unwind_functions",
        &Binary::unwind_functions,
        "Return list of " RST_CLASS_REF(lief.Function) " found in the ``__unwind_info`` section"_doc)

    .def_prop_ro("functions",
        &Binary::functions,
        "Return list of **all** " RST_CLASS_REF(lief.Function) " found"_doc)

    .def("get_section",
        nb::overload_cast<const std::string&, const std::string&>(&Binary::get_section),
        R"delim(
        Return the section from the segment with the name
        given in the first parameter and with the section's name provided in the
        second parameter. If the section cannot be found, it returns a nullptr
        )delim"_doc,
        "segname"_a, "secname"_a,
        nb::rv_policy::reference_internal)

    .def("shift",
         [] (Binary& self, size_t width) {
           return error_or(&Binary::shift, self, width);
         },
         R"delim(
         Shift the content located right after the Load commands table.
         This operation can be used to add a new command
         )delim"_doc,
         "value"_a)

    .def("shift_linkedit",
         [] (Binary& self, size_t width) {
           return error_or(&Binary::shift_linkedit, self, width);
         },
         "Shift the position on the __LINKEDIT data by `width`"_doc,
         "value"_a)

    .def("add_exported_function",
        &Binary::add_exported_function,
        "Add a new export in the binary"_doc,
        "address"_a, "name"_a,
        nb::rv_policy::reference_internal)

    .def("add_local_symbol",
        &Binary::add_local_symbol,
        "Add a new a new symbol in the LC_SYMTAB"_doc,
        "address"_a, "name"_a,
        nb::rv_policy::reference_internal)

    .def_prop_ro("page_size",
        &Binary::page_size,
        "Return the binary's page size"_doc)

    .def_prop_ro("has_nx_heap", &Binary::has_nx_heap,
                 R"doc(
                 Return True if the **heap** is flagged as non-executable. False
                 otherwise.
                 )doc"_doc)

    .def_prop_ro("has_nx_stack", &Binary::has_nx_stack,
                 R"doc(
                 Return True if the **stack** is flagged as non-executable. False
                 otherwise.
                 )doc"_doc)

    .def_prop_ro("support_arm64_ptr_auth", &Binary::support_arm64_ptr_auth,
      R"doc(
      Check if the binary is supporting ARM64 pointer authentication (arm64e)
      )doc"
    )

    .def_prop_ro("objc_metadata", &Binary::objc_metadata,
      R"doc(
      Return Objective-C metadata info if present

      .. warning::

        This is only available with the extended version of LIEF.
      )doc"_doc
    )

    .def("__getitem__",
        nb::overload_cast<LoadCommand::TYPE>(&Binary::operator[]),
        nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<LoadCommand::TYPE>(&Binary::has, nb::const_))

    .def_prop_ro("overlay",
        [] (const Binary& self) {
          const span<const uint8_t> overlay = self.overlay();
          return nb::memoryview::from_memory(overlay.data(), overlay.size());
        })

    LIEF_DEFAULT_STR(Binary);
}
}

