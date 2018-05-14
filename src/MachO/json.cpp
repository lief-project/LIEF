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

#include "LIEF/config.h"
#include "LIEF/hash.hpp"

#ifdef LIEF_JSON_SUPPORT
#include "Object.tcc"

#include "LIEF/MachO/json.hpp"

#include "LIEF/MachO.hpp"
namespace LIEF {
namespace MachO {


json to_json(const Object& v) {
  JsonVisitor visitor;
  visitor(v);
  return visitor.get();
}


std::string to_json_str(const Object& v) {
  return MachO::to_json(v).dump();
}


void JsonVisitor::visit(const Binary& binary) {
  JsonVisitor header_visitor;
  header_visitor(binary.header());

  // Sections
  std::vector<json> sections;
  for (const Section& section : binary.sections()) {
    JsonVisitor visitor;
    visitor(section);
    sections.emplace_back(visitor.get());
  }

  // Segments
  std::vector<json> segments;
  for (const SegmentCommand& segment : binary.segments()) {
    JsonVisitor visitor;
    visitor(segment);
    segments.emplace_back(visitor.get());
  }

  // Symbols
  std::vector<json> symbols;
  for (const Symbol& sym : binary.symbols()) {
    JsonVisitor visitor;
    visitor(sym);
    symbols.emplace_back(visitor.get());
  }

  // Relocations
  std::vector<json> relocations;
  for (const Relocation& r : binary.relocations()) {
    JsonVisitor visitor;
    visitor(r);
    relocations.emplace_back(visitor.get());
  }

  std::vector<json> libraries;
  for (const DylibCommand& lib : binary.libraries()) {
    JsonVisitor visitor;
    visitor(lib);
    libraries.emplace_back(visitor.get());
  }


  this->node_["header"]      = header_visitor.get();
  this->node_["sections"]    = sections;
  this->node_["segments"]    = segments;
  this->node_["symbols"]     = symbols;
  this->node_["relocations"] = relocations;
  this->node_["libraries"]   = libraries;

  if (binary.has_uuid()) {
    JsonVisitor v;
    v(binary.uuid());
    this->node_["uuid"] = v.get();
  }

  if (binary.has_main_command()) {
    JsonVisitor v;
    v(binary.main_command());
    this->node_["main_command"] = v.get();
  }

  if (binary.has_dylinker()) {
    JsonVisitor v;
    v(binary.dylinker());
    this->node_["dylinker"] = v.get();
  }

  if (binary.has_dyld_info()) {
    JsonVisitor v;
    v(binary.dyld_info());
    this->node_["dyld_info"] = v.get();
  }

  if (binary.has_function_starts()) {
    JsonVisitor v;
    v(binary.function_starts());
    this->node_["function_starts"] = v.get();
  }

  if (binary.has_source_version()) {
    JsonVisitor v;
    v(binary.source_version());
    this->node_["source_version"] = v.get();
  }

  if (binary.has_version_min()) {
    JsonVisitor v;
    v(binary.version_min());
    this->node_["version_min"] = v.get();
  }

  if (binary.has_thread_command()) {
    JsonVisitor v;
    v(binary.thread_command());
    this->node_["thread_command"] = v.get();
  }

  if (binary.has_rpath()) {
    JsonVisitor v;
    v(binary.rpath());
    this->node_["rpath"] = v.get();
  }

  if (binary.has_symbol_command()) {
    JsonVisitor v;
    v(binary.symbol_command());
    this->node_["symbol_command"] = v.get();
  }

  if (binary.has_dynamic_symbol_command()) {
    JsonVisitor v;
    v(binary.dynamic_symbol_command());
    this->node_["dynamic_symbol_command"] = v.get();
  }

  if (binary.has_code_signature()) {
    JsonVisitor v;
    v(binary.code_signature());
    this->node_["code_signature"] = v.get();
  }

  if (binary.has_data_in_code()) {
    JsonVisitor v;
    v(binary.data_in_code());
    this->node_["data_in_code"] = v.get();
  }
}


void JsonVisitor::visit(const Header& header) {

  std::vector<json> flags;
  for (HEADER_FLAGS f : header.flags_list()) {
    flags.emplace_back(to_string(f));
  }
  this->node_["magic"]       = to_string(header.magic());
  this->node_["cpu_type"]    = to_string(header.cpu_type());
  this->node_["cpu_subtype"] = header.cpu_subtype();
  this->node_["file_type"]   = to_string(header.file_type());
  this->node_["nb_cmds"]     = header.nb_cmds();
  this->node_["sizeof_cmds"] = header.sizeof_cmds();
  this->node_["reserved"]    = header.reserved();
  this->node_["flags"]       = flags;
}


void JsonVisitor::visit(const LoadCommand& cmd) {
  this->node_["command"]        = to_string(cmd.command());
  this->node_["command_size"]   = cmd.size();
  this->node_["command_offset"] = cmd.command_offset();
  this->node_["data_hash"]      = Hash::hash(cmd.data());
}

void JsonVisitor::visit(const UUIDCommand& uuid) {
  this->visit(*uuid.as<LoadCommand>());
  this->node_["uuid"] = uuid.uuid();
}

void JsonVisitor::visit(const SymbolCommand& symbol) {
  this->visit(*symbol.as<LoadCommand>());
  this->node_["symbol_offset"]    = symbol.symbol_offset();
  this->node_["numberof_symbols"] = symbol.numberof_symbols();
  this->node_["strings_offset"]   = symbol.strings_offset();
  this->node_["strings_size"]     = symbol.strings_size();
}

void JsonVisitor::visit(const SegmentCommand& segment) {

  std::vector<json> sections;
  for (const Section& section : segment.sections()) {
    sections.push_back(section.name());
  }

  this->visit(*segment.as<LoadCommand>());
  this->node_["name"]              = segment.name();
  this->node_["virtual_address"]   = segment.virtual_address();
  this->node_["virtual_size"]      = segment.virtual_size();
  this->node_["file_size"]         = segment.file_size();
  this->node_["file_offset"]       = segment.file_offset();
  this->node_["max_protection"]    = segment.max_protection();
  this->node_["init_protection"]   = segment.init_protection();
  this->node_["numberof_sections"] = segment.numberof_sections();
  this->node_["flags"]             = segment.flags();
  this->node_["sections"]          = sections;
  this->node_["content_hash"]      = Hash::hash(segment.content());
}

void JsonVisitor::visit(const Section& section) {

  std::vector<json> flags;
  for (MACHO_SECTION_FLAGS f : section.flags_list()) {
    flags.emplace_back(to_string(f));
  }
  this->node_["name"]                 = section.name();
  this->node_["virtual_address"]      = section.virtual_address();
  this->node_["offset"]               = section.offset();
  this->node_["size"]                 = section.size();
  this->node_["alignment"]            = section.alignment();
  this->node_["relocation_offset"]    = section.relocation_offset();
  this->node_["numberof_relocations"] = section.numberof_relocations();
  this->node_["flags"]                = section.flags();
  this->node_["type"]                 = to_string(section.type());
  this->node_["reserved1"]            = section.reserved1();
  this->node_["reserved2"]            = section.reserved2();
  this->node_["reserved3"]            = section.reserved3();
  this->node_["content_hash"]         = Hash::hash(section.content());
}

void JsonVisitor::visit(const MainCommand& maincmd) {
  this->visit(*maincmd.as<LoadCommand>());

  this->node_["entrypoint"] = maincmd.entrypoint();
  this->node_["stack_size"] = maincmd.stack_size();
}

void JsonVisitor::visit(const DynamicSymbolCommand& dynamic_symbol) {
  this->visit(*dynamic_symbol.as<LoadCommand>());

  this->node_["idx_local_symbol"]                 = dynamic_symbol.idx_local_symbol();
  this->node_["nb_local_symbols"]                 = dynamic_symbol.nb_local_symbols();
  this->node_["idx_external_define_symbol"]       = dynamic_symbol.idx_external_define_symbol();
  this->node_["nb_external_define_symbols"]       = dynamic_symbol.nb_external_define_symbols();
  this->node_["idx_undefined_symbol"]             = dynamic_symbol.idx_undefined_symbol();
  this->node_["nb_undefined_symbols"]             = dynamic_symbol.nb_undefined_symbols();
  this->node_["toc_offset"]                       = dynamic_symbol.toc_offset();
  this->node_["nb_toc"]                           = dynamic_symbol.nb_toc();
  this->node_["module_table_offset"]              = dynamic_symbol.module_table_offset();
  this->node_["nb_module_table"]                  = dynamic_symbol.nb_module_table();
  this->node_["external_reference_symbol_offset"] = dynamic_symbol.external_reference_symbol_offset();
  this->node_["nb_external_reference_symbols"]    = dynamic_symbol.nb_external_reference_symbols();
  this->node_["indirect_symbol_offset"]           = dynamic_symbol.indirect_symbol_offset();
  this->node_["nb_indirect_symbols"]              = dynamic_symbol.nb_indirect_symbols();
  this->node_["external_relocation_offset"]       = dynamic_symbol.external_relocation_offset();
  this->node_["nb_external_relocations"]          = dynamic_symbol.nb_external_relocations();
  this->node_["local_relocation_offset"]          = dynamic_symbol.local_relocation_offset();
  this->node_["nb_local_relocations"]             = dynamic_symbol.nb_local_relocations();
}

void JsonVisitor::visit(const DylinkerCommand& dylinker) {
  this->visit(*dylinker.as<LoadCommand>());

  this->node_["name"] = dylinker.name();
}

void JsonVisitor::visit(const DylibCommand& dylib) {
  this->visit(*dylib.as<LoadCommand>());

  this->node_["name"]                  = dylib.name();
  this->node_["timestamp"]             = dylib.timestamp();
  this->node_["current_version"]       = dylib.current_version();
  this->node_["compatibility_version"] = dylib.compatibility_version();
}

void JsonVisitor::visit(const ThreadCommand& threadcmd) {
  this->visit(*threadcmd.as<LoadCommand>());

  this->node_["flavor"] = threadcmd.flavor();
  this->node_["count"]  = threadcmd.count();
  this->node_["pc"]     = threadcmd.pc();
}

void JsonVisitor::visit(const RPathCommand& rpath) {
  this->visit(*rpath.as<LoadCommand>());

  this->node_["path"] = rpath.path();
}

void JsonVisitor::visit(const Symbol& symbol) {
  this->node_["name"]              = symbol.name();
  this->node_["type"]              = symbol.type();
  this->node_["numberof_sections"] = symbol.numberof_sections();
  this->node_["description"]       = symbol.description();
  this->node_["value"]             = symbol.value();
  this->node_["origin"]            = to_string(symbol.origin());
  this->node_["is_external"]       = symbol.is_external();

  if (symbol.has_export_info()) {
    JsonVisitor v;
    v(symbol.export_info());
    this->node_["export_info"] = v.get();
  }

  if (symbol.has_binding_info()) {
    JsonVisitor v;
    v(symbol.binding_info());
    this->node_["binding_info"] = v.get();
  }
}

void JsonVisitor::visit(const Relocation& relocation) {

  this->node_["is_pc_relative"] = relocation.is_pc_relative();
  this->node_["architecture"]   = to_string(relocation.architecture());
  this->node_["origin"]         = to_string(relocation.origin());
  if (relocation.has_symbol()) {
    this->node_["symbol"] = relocation.symbol().name();
  }

  if (relocation.has_section()) {
    this->node_["section"] = relocation.section().name();
  }

  if (relocation.has_segment()) {
    this->node_["segment"] = relocation.segment().name();
  }
}

void JsonVisitor::visit(const RelocationObject& robject) {
  this->visit(*robject.as<Relocation>());

  this->node_["value"]        = robject.value();
  this->node_["is_scattered"] = robject.is_scattered();
}

void JsonVisitor::visit(const RelocationDyld& rdyld) {
  this->visit(*rdyld.as<Relocation>());
}

void JsonVisitor::visit(const BindingInfo& binding) {
  this->node_["address"]         = binding.address();
  this->node_["binding_class"]   = to_string(binding.binding_class());
  this->node_["binding_type"]    = to_string(binding.binding_type());
  this->node_["library_ordinal"] = binding.library_ordinal();
  this->node_["addend"]          = binding.addend();
  this->node_["is_weak_import"]  = binding.is_weak_import();

  if (binding.has_symbol()) {
    this->node_["symbol"] = binding.symbol().name();
  }

  if (binding.has_segment()) {
    this->node_["segment"] = binding.segment().name();
  }

  if (binding.has_library()) {
    this->node_["library"] = binding.library().name();
  }

}

void JsonVisitor::visit(const ExportInfo& einfo) {

  this->node_["flags"]   = einfo.flags();
  this->node_["address"] = einfo.address();

  if (einfo.has_symbol()) {
    this->node_["symbol"] = einfo.symbol().name();
  }
}

void JsonVisitor::visit(const FunctionStarts& fs) {
  this->visit(*fs.as<LoadCommand>());

  this->node_["data_offset"] = fs.data_offset();
  this->node_["data_size"]   = fs.data_size();
  this->node_["functions"]   = fs.functions();
}

void JsonVisitor::visit(const CodeSignature& cs) {
  this->visit(*cs.as<LoadCommand>());
  this->node_["data_offset"] = cs.data_offset();
  this->node_["data_size"]   = cs.data_size();
}

void JsonVisitor::visit(const DataInCode& dic) {
  this->visit(*dic.as<LoadCommand>());
  std::vector<json> entries;
  for (const DataCodeEntry& e : dic.entries()) {
    JsonVisitor v;
    v(e);
    entries.emplace_back(std::move(v.get()));
  }

  this->node_["data_offset"] = dic.data_offset();
  this->node_["data_size"]   = dic.data_size();
  this->node_["entries"]     = entries;
}

void JsonVisitor::visit(const DataCodeEntry& dce) {
  this->node_["offset"] = dce.offset();
  this->node_["length"] = dce.length();
  this->node_["type"]   = to_string(dce.type());
}


void JsonVisitor::visit(const SourceVersion& sv) {
  this->visit(*sv.as<LoadCommand>());
  this->node_["version"] = sv.version();
}


void JsonVisitor::visit(const VersionMin& vmin) {
  this->visit(*vmin.as<LoadCommand>());

  this->node_["version"] = vmin.version();
  this->node_["sdk"]     = vmin.sdk();
}

void JsonVisitor::visit(const SegmentSplitInfo& ssi) {
  this->visit(*ssi.as<LoadCommand>());
  this->node_["data_offset"] = ssi.data_offset();
  this->node_["data_size"]   = ssi.data_size();
}

void JsonVisitor::visit(const SubFramework& sf) {
  this->visit(*sf.as<LoadCommand>());
  this->node_["umbrella"] = sf.umbrella();
}

void JsonVisitor::visit(const DyldEnvironment& dv) {
  this->visit(*dv.as<LoadCommand>());
  this->node_["value"] = dv.value();
}




} // namespace MachO
} // namespace LIEF

#endif // LIEF_JSON_SUPPORT
