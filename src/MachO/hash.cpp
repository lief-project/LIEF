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

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO.hpp"
#include "Object.tcc"

namespace LIEF {
namespace MachO {

Hash::~Hash(void) = default;

size_t Hash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::MachO::Hash>(obj);
}

void Hash::visit(const Binary& binary) {
  this->process(binary.header());
  this->process(std::begin(binary.commands()), std::end(binary.commands()));
  this->process(std::begin(binary.symbols()), std::end(binary.symbols()));
}


void Hash::visit(const Header& header) {
  this->process(header.magic());
  this->process(header.cpu_type());
  this->process(header.cpu_subtype());
  this->process(header.file_type());
  this->process(header.nb_cmds());
  this->process(header.sizeof_cmds());
  this->process(header.flags());
  this->process(header.reserved());
}

void Hash::visit(const LoadCommand& cmd) {
  this->process(cmd.command());
  this->process(cmd.size());
  this->process(cmd.data());
  this->process(cmd.command_offset());
}

void Hash::visit(const UUIDCommand& uuid) {
  this->visit(*uuid.as<LoadCommand>());
  this->process(uuid.uuid());
}

void Hash::visit(const SymbolCommand& symbol) {

  this->visit(*symbol.as<LoadCommand>());
  this->process(symbol.symbol_offset());
  this->process(symbol.numberof_symbols());
  this->process(symbol.strings_offset());
  this->process(symbol.strings_size());
}

void Hash::visit(const SegmentCommand& segment) {

  this->visit(*segment.as<LoadCommand>());
  this->process(segment.name());
  this->process(segment.virtual_address());
  this->process(segment.virtual_size());
  this->process(segment.file_size());
  this->process(segment.file_offset());
  this->process(segment.max_protection());
  this->process(segment.init_protection());
  this->process(segment.numberof_sections());
  this->process(segment.flags());
  this->process(segment.content());
  this->process(std::begin(segment.sections()), std::end(segment.sections()));
}

void Hash::visit(const Section& section) {
  this->visit(*section.as<LoadCommand>());

  this->process(section.content());
  this->process(section.segment_name());
  this->process(section.address());
  this->process(section.alignment());
  this->process(section.relocation_offset());
  this->process(section.numberof_relocations());
  this->process(section.flags());
  this->process(section.type());
  this->process(section.reserved1());
  this->process(section.reserved2());
  this->process(section.reserved3());
  this->process(section.raw_flags());
  this->process(std::begin(section.relocations()), std::end(section.relocations()));
}

void Hash::visit(const MainCommand& maincmd) {

  this->visit(*maincmd.as<LoadCommand>());

  this->process(maincmd.entrypoint());
  this->process(maincmd.stack_size());
}

void Hash::visit(const DynamicSymbolCommand& dynamic_symbol) {
  this->visit(*dynamic_symbol.as<LoadCommand>());
  this->process(dynamic_symbol.idx_local_symbol());
  this->process(dynamic_symbol.nb_local_symbols());

  this->process(dynamic_symbol.idx_external_define_symbol());
  this->process(dynamic_symbol.nb_external_define_symbols());

  this->process(dynamic_symbol.idx_undefined_symbol());
  this->process(dynamic_symbol.nb_undefined_symbols());

  this->process(dynamic_symbol.toc_offset());
  this->process(dynamic_symbol.nb_toc());

  this->process(dynamic_symbol.module_table_offset());
  this->process(dynamic_symbol.nb_module_table());

  this->process(dynamic_symbol.external_reference_symbol_offset());
  this->process(dynamic_symbol.nb_external_reference_symbols());

  this->process(dynamic_symbol.indirect_symbol_offset());
  this->process(dynamic_symbol.nb_indirect_symbols());

  this->process(dynamic_symbol.external_relocation_offset());
  this->process(dynamic_symbol.nb_external_relocations());

  this->process(dynamic_symbol.local_relocation_offset());
  this->process(dynamic_symbol.nb_local_relocations());
}

void Hash::visit(const DylinkerCommand& dylinker) {
  this->visit(*dylinker.as<LoadCommand>());
  this->process(dylinker.name());
}

void Hash::visit(const DylibCommand& dylib) {
  this->visit(*dylib.as<LoadCommand>());

  this->process(dylib.name());
  this->process(dylib.timestamp());
  this->process(dylib.current_version());
  this->process(dylib.compatibility_version());
}

void Hash::visit(const ThreadCommand& threadcmd) {
  this->visit(*threadcmd.as<LoadCommand>());
  this->process(threadcmd.flavor());
  this->process(threadcmd.count());
  this->process(threadcmd.state());
}

void Hash::visit(const RPathCommand& rpath) {
  this->visit(*rpath.as<LoadCommand>());
  this->process(rpath.path());
}

void Hash::visit(const Symbol& symbol) {
  this->process(symbol.name());
  this->process(symbol.type());
  this->process(symbol.numberof_sections());
  this->process(symbol.description());
  this->process(symbol.value());

  if (symbol.has_binding_info()) {
    this->process(symbol.binding_info());
  }

  if (symbol.has_export_info()) {
    this->process(symbol.export_info());
  }
}

void Hash::visit(const Relocation& relocation) {

  this->process(relocation.size());
  this->process(relocation.address());
  this->process(relocation.is_pc_relative());
  this->process(relocation.type());
  this->process(relocation.origin());

  if (relocation.has_symbol()) {
    this->process(relocation.symbol().name());
  }
}

void Hash::visit(const RelocationObject& robject) {

  this->visit(*robject.as<Relocation>());
  this->process(robject.is_scattered());
  if (robject.is_scattered()) {
    this->process(robject.value());
  }
}

void Hash::visit(const RelocationDyld& rdyld) {
  this->visit(*rdyld.as<Relocation>());
}

void Hash::visit(const BindingInfo& binding) {

  this->process(binding.binding_class());
  this->process(binding.binding_type());
  this->process(binding.library_ordinal());
  this->process(binding.addend());
  this->process(binding.is_weak_import());
  this->process(binding.address());

  if (binding.has_symbol()) {
    this->process(binding.symbol().name());
  }

  if (binding.has_library()) {
    this->process(binding.library());
  }
}

void Hash::visit(const ExportInfo& einfo) {
  this->process(einfo.node_offset());
  this->process(einfo.flags());
  this->process(einfo.address());

  if (einfo.has_symbol()) {
    this->process(einfo.symbol().name());
  }
}

void Hash::visit(const FunctionStarts& fs) {
  this->visit(*fs.as<LoadCommand>());
  this->process(fs.data_offset());
  this->process(fs.data_size());
  this->process(fs.functions());

}

void Hash::visit(const CodeSignature& cs) {
  this->visit(*cs.as<LoadCommand>());
  this->process(cs.data_offset());
  this->process(cs.data_size());
}

void Hash::visit(const DataInCode& dic) {
  this->visit(*dic.as<LoadCommand>());
  this->process(dic.data_offset());
  this->process(dic.data_size());
  this->process(std::begin(dic.entries()), std::end(dic.entries()));
}

void Hash::visit(const DataCodeEntry& dce) {
  this->process(dce.offset());
  this->process(dce.length());
  this->process(dce.type());
}

void Hash::visit(const VersionMin& vmin) {
  this->visit(*vmin.as<LoadCommand>());
  this->process(vmin.version());
  this->process(vmin.sdk());
}

void Hash::visit(const SourceVersion& sv) {
  this->visit(*sv.as<LoadCommand>());
  this->process(sv.version());
}

void Hash::visit(const SegmentSplitInfo& ssi) {
  this->visit(*ssi.as<LoadCommand>());
  this->process(ssi.data_offset());
  this->process(ssi.data_size());
}

void Hash::visit(const SubFramework& sf) {
  this->visit(*sf.as<LoadCommand>());
  this->process(sf.umbrella());
}

void Hash::visit(const DyldEnvironment& de) {
  this->visit(*de.as<LoadCommand>());
  this->process(de.value());
}





} // namespace MachO
} // namespace LIEF

