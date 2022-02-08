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

#include "ELF/json_internal.hpp"
#include "LIEF/ELF.hpp"

namespace LIEF {
namespace ELF {

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
  for (const Segment& segment : binary.segments()) {
    JsonVisitor visitor;
    visitor(segment);
    segments.emplace_back(visitor.get());
  }

  // Dynamic entries
  std::vector<json> dynamic_entries;
  for (const DynamicEntry& entry : binary.dynamic_entries()) {
    JsonVisitor visitor;
    entry.accept(visitor);
    dynamic_entries.emplace_back(visitor.get());
  }


  // Dynamic symbols
  std::vector<json> dynamic_symbols;
  for (const Symbol& symbol : binary.dynamic_symbols()) {
    JsonVisitor visitor;
    visitor(symbol);
    dynamic_symbols.emplace_back(visitor.get());
  }


  // Static symbols
  std::vector<json> static_symbols;
  for (const Symbol& symbol : binary.static_symbols()) {
    JsonVisitor visitor;
    visitor(symbol);
    static_symbols.emplace_back(visitor.get());
  }


  // Dynamic relocations
  std::vector<json> dynamic_relocations;
  for (const Relocation& reloc : binary.dynamic_relocations()) {
    JsonVisitor visitor;
    visitor(reloc);
    dynamic_relocations.emplace_back(visitor.get());
  }


  // pltgot relocations
  std::vector<json> pltgot_relocations;
  for (const Relocation& reloc : binary.pltgot_relocations()) {
    JsonVisitor visitor;
    visitor(reloc);
    pltgot_relocations.emplace_back(visitor.get());
  }


  // Symbol version
  std::vector<json> symbols_version;
  for (const SymbolVersion& s : binary.symbols_version()) {
    JsonVisitor visitor;
    visitor(s);
    symbols_version.emplace_back(visitor.get());
  }


  // Symbols version requirement
  std::vector<json> symbols_version_requirement;
  for (const SymbolVersionRequirement& s : binary.symbols_version_requirement()) {
    JsonVisitor visitor;
    visitor(s);
    symbols_version_requirement.emplace_back(visitor.get());
  }


  // Symbols version definition
  std::vector<json> symbols_version_definition;
  for (const SymbolVersionDefinition& s : binary.symbols_version_definition()) {
    JsonVisitor visitor;
    visitor(s);
    symbols_version_definition.emplace_back(visitor.get());
  }


  // Notes
  std::vector<json> notes;
  for (const Note& note : binary.notes()) {
    JsonVisitor visitor;
    visitor(note);
    notes.emplace_back(visitor.get());
  }

  node_["name"]         = binary.name();
  node_["entrypoint"]   = binary.entrypoint();
  node_["imagebase"]    = binary.imagebase();
  node_["virtual_size"] = binary.virtual_size();
  node_["is_pie"]       = binary.is_pie();

  if (binary.has_interpreter()) {
    node_["interpreter"] = binary.interpreter();
  }

  node_["header"]                      = header_visitor.get();
  node_["sections"]                    = sections;
  node_["segments"]                    = segments;
  node_["dynamic_entries"]             = dynamic_entries;
  node_["dynamic_symbols"]             = dynamic_symbols;
  node_["static_symbols"]              = static_symbols;
  node_["dynamic_relocations"]         = dynamic_relocations;
  node_["pltgot_relocations"]          = pltgot_relocations;
  node_["symbols_version"]             = symbols_version;
  node_["symbols_version_requirement"] = symbols_version_requirement;
  node_["symbols_version_definition"]  = symbols_version_definition;
  node_["notes"]                       = notes;

  if (binary.use_gnu_hash()) {
    JsonVisitor gnu_hash_visitor;
    gnu_hash_visitor(*binary.gnu_hash());

    node_["gnu_hash"] = gnu_hash_visitor.get();
  }

  if (binary.use_sysv_hash()) {
    JsonVisitor sysv_hash_visitor;
    sysv_hash_visitor(*binary.sysv_hash());

    node_["sysv_hash"] = sysv_hash_visitor.get();
  }

}


void JsonVisitor::visit(const Header& header) {
  node_["file_type"]                       = to_string(header.file_type());
  node_["machine_type"]                    = to_string(header.machine_type());
  node_["object_file_version"]             = to_string(header.object_file_version());
  node_["entrypoint"]                      = header.entrypoint();
  node_["program_headers_offset"]          = header.program_headers_offset();
  node_["section_headers_offset"]          = header.section_headers_offset();
  node_["processor_flag"]                  = header.processor_flag();
  node_["header_size"]                     = header.header_size();
  node_["program_header_size"]             = header.program_header_size();
  node_["processornumberof_segments_flag"] = header.numberof_segments();
  node_["section_header_size"]             = header.section_header_size();
  node_["numberof_sections"]               = header.numberof_sections();
  node_["section_name_table_idx"]          = header.section_name_table_idx();
  node_["identity_class"]                  = to_string(header.identity_class());
  node_["identity_data"]                   = to_string(header.identity_data());
  node_["identity_version"]                = to_string(header.identity_version());
  node_["identity_os_abi"]                 = to_string(header.identity_os_abi());
  node_["identity_abi_version"]            = header.identity_abi_version();
}


void JsonVisitor::visit(const Section& section) {
  std::vector<json> flags;
  for (ELF_SECTION_FLAGS f : section.flags_list()) {
    flags.emplace_back(to_string(f));
  }

  node_["name"]            = section.name();
  node_["virtual_address"] = section.virtual_address();
  node_["size"]            = section.size();
  node_["offset"]          = section.offset();
  node_["alignment"]       = section.alignment();
  node_["information"]     = section.information();
  node_["entry_size"]      = section.entry_size();
  node_["link"]            = section.link();
  node_["type"]            = to_string(section.type());
  node_["flags"]           = flags;
}

void JsonVisitor::visit(const Segment& segment) {

  std::vector<json> sections;
  for (const Section& section : segment.sections()) {
    sections.emplace_back(section.name());
  }

  node_["type"]             = to_string(segment.type());
  node_["flags"]            = static_cast<size_t>(segment.flags());
  node_["file_offset"]      = segment.file_offset();
  node_["virtual_address"]  = segment.virtual_address();
  node_["physical_address"] = segment.physical_address();
  node_["physical_size"]    = segment.physical_size();
  node_["virtual_size"]     = segment.virtual_size();
  node_["alignment"]        = segment.alignment();
  node_["sections"]         = sections;

}

void JsonVisitor::visit(const DynamicEntry& entry) {
  node_["tag"]   = to_string(entry.tag());
  node_["value"] = entry.value();
}


void JsonVisitor::visit(const DynamicEntryArray& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  node_["array"] = entry.array();
}


void JsonVisitor::visit(const DynamicEntryLibrary& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  node_["library"] = entry.name();
}


void JsonVisitor::visit(const DynamicEntryRpath& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  node_["rpath"] = entry.rpath();
}


void JsonVisitor::visit(const DynamicEntryRunPath& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  node_["runpath"] = entry.runpath();
}


void JsonVisitor::visit(const DynamicSharedObject& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  node_["library"] = entry.name();
}


void JsonVisitor::visit(const DynamicEntryFlags& entry) {
  visit(static_cast<const DynamicEntry&>(entry));

  const DynamicEntryFlags::flags_list_t& flags = entry.flags();
  std::vector<std::string> flags_str;
  flags_str.reserve(flags.size());

  if (entry.tag() == DYNAMIC_TAGS::DT_FLAGS) {
    std::transform(
        std::begin(flags), std::end(flags),
        std::back_inserter(flags_str),
        [] (uint32_t f) {
          return to_string(static_cast<DYNAMIC_FLAGS>(f));
        });
  }

  if (entry.tag() == DYNAMIC_TAGS::DT_FLAGS_1) {
    std::transform(
        std::begin(flags), std::end(flags),
        std::back_inserter(flags_str),
        [] (uint32_t f) {
          return to_string(static_cast<DYNAMIC_FLAGS_1>(f));
        });
  }

  node_["flags"] = flags_str;
}

void JsonVisitor::visit(const Symbol& symbol) {
  node_["type"]        = to_string(symbol.type());
  node_["binding"]     = to_string(symbol.binding());
  node_["information"] = symbol.information();
  node_["other"]       = symbol.other();
  node_["value"]       = symbol.value();
  node_["size"]        = symbol.size();
  node_["name"]        = symbol.name();

  std::string sname = symbol.demangled_name();
  if (sname.empty()) {
    sname = symbol.name();
  }
  node_["demangled_name"] = sname;
}

void JsonVisitor::visit(const Relocation& relocation) {
  std::string relocation_type = "NOT_TO_STRING";
  std::string symbol_name;
  std::string section_name;

  const Symbol* s = relocation.symbol();
  if (s != nullptr) {
    symbol_name = s->demangled_name();
    if (symbol_name.empty()) {
      symbol_name = s->name();
    }
  }
  const Section* reloc_sec = relocation.section();
  if (reloc_sec != nullptr) {
    section_name = reloc_sec->name();
  }


  if (relocation.architecture() == ARCH::EM_X86_64) {
    relocation_type = to_string(static_cast<RELOC_x86_64>(relocation.type()));
  }

  node_["symbol_name"] = symbol_name;
  node_["address"]     = relocation.address();
  node_["type"]        = relocation_type;
  node_["section"]     = section_name;

}

void JsonVisitor::visit(const SymbolVersion& sv) {
  node_["value"] = sv.value();
  if (sv.has_auxiliary_version()) {
   node_["symbol_version_auxiliary"] = sv.symbol_version_auxiliary()->name();
  }

}

void JsonVisitor::visit(const SymbolVersionRequirement& svr) {

  std::vector<json> svar_json;

  for (const SymbolVersionAuxRequirement& svar : svr.auxiliary_symbols()) {
    JsonVisitor visitor;
    visitor(svar);
    svar_json.emplace_back(visitor.get());
  }

  node_["version"]                              = svr.version();
  node_["name"]                                 = svr.name();
  node_["symbol_version_auxiliary_requirement"] = svar_json;

}

void JsonVisitor::visit(const SymbolVersionDefinition& svd) {

  std::vector<json> sva_json;

  for (const SymbolVersionAux& sva : svd.symbols_aux()) {
    JsonVisitor visitor;
    visitor(sva);
    sva_json.emplace_back(visitor.get());
  }

  node_["version"]                  = svd.version();
  node_["flags"]                    = svd.flags();
  node_["hash"]                     = svd.hash();
  node_["symbol_version_auxiliary"] = sva_json;
}

void JsonVisitor::visit(const SymbolVersionAux& sv) {
  node_["name"] = sv.name();
}

void JsonVisitor::visit(const SymbolVersionAuxRequirement& svar) {
  node_["hash"]  = svar.hash();
  node_["flags"] = svar.flags();
  node_["other"] = svar.other();
}

void JsonVisitor::visit(const Note& note) {
  node_["name"]  = note.name();
  const std::string type_str = note.is_core() ? to_string(note.type_core()) : to_string(note.type());
  node_["type"]  = type_str;
  JsonVisitor visitor;
  const NoteDetails& d = note.details();
  d.accept(visitor);
  node_["details"] = visitor.get();
}

void JsonVisitor::visit(const NoteDetails&) {
  node_ = json::object();
}

void JsonVisitor::visit(const NoteAbi& note_abi) {
  node_["abi"]     = to_string(note_abi.abi());
  node_["version"] = note_abi.version();
}

void JsonVisitor::visit(const CorePrPsInfo& pinfo) {
  node_["file_name"] = pinfo.file_name();
  node_["flags"]     = pinfo.flags();
  node_["uid"]       = pinfo.uid();
  node_["gid"]       = pinfo.gid();
  node_["pid"]       = pinfo.pid();
  node_["ppid"]      = pinfo.ppid();
  node_["pgrp"]      = pinfo.pgrp();
  node_["sid"]       = pinfo.sid();
}


void JsonVisitor::visit(const CorePrStatus& pstatus) {
  node_["current_sig"] = pstatus.current_sig();
  node_["sigpend"]     = pstatus.sigpend();
  node_["sighold"]     = pstatus.sighold();
  node_["pid"]         = pstatus.pid();
  node_["ppid"]        = pstatus.ppid();
  node_["pgrp"]        = pstatus.pgrp();
  node_["sid"]         = pstatus.sid();
  node_["sigpend"]     = pstatus.sigpend();

  node_["utime"] = {
    {"tv_sec",  pstatus.utime().sec},
    {"tv_usec", pstatus.utime().usec}
  };

  node_["stime"] = {
    {"tv_sec",  pstatus.stime().sec},
    {"tv_usec", pstatus.stime().sec}
  };

  node_["stime"] = {
    {"tv_sec",  pstatus.stime().sec},
    {"tv_usec", pstatus.stime().usec}
  };

  json regs;
  for (const CorePrStatus::reg_context_t::value_type& val : pstatus.reg_context()) {
    regs[to_string(val.first)] = val.second;
  };
  node_["regs"] = regs;
}

void JsonVisitor::visit(const CoreAuxv& auxv) {
  std::vector<json> values;
  for (const CoreAuxv::val_context_t::value_type& val : auxv.values()) {
    node_[to_string(val.first)] = val.second;
  }
}

void JsonVisitor::visit(const CoreSigInfo& siginfo) {
  node_["signo"] = siginfo.signo();
  node_["sigcode"] = siginfo.sigcode();
  node_["sigerrno"] = siginfo.sigerrno();
}

void JsonVisitor::visit(const CoreFile& file) {
  std::vector<json> files;
  for (const CoreFileEntry& entry : file.files()) {
    const json file = {
      {"start",    entry.start},
      {"end",      entry.end},
      {"file_ofs", entry.file_ofs},
      {"path",     entry.path}
    };
    files.emplace_back(file);
  }
  node_["files"] = files;
  node_["count"] = file.count();
}

void JsonVisitor::visit(const GnuHash& gnuhash) {
  node_["nb_buckets"]    = gnuhash.nb_buckets();
  node_["symbol_index"]  = gnuhash.symbol_index();
  node_["shift2"]        = gnuhash.shift2();
  node_["maskwords"]     = gnuhash.maskwords();
  node_["bloom_filters"] = gnuhash.bloom_filters();
  node_["buckets"]       = gnuhash.buckets();
  node_["hash_values"]   = gnuhash.hash_values();
}


void JsonVisitor::visit(const SysvHash& sysvhash) {
  node_["nbucket"] = sysvhash.nbucket();
  node_["nchain"]  = sysvhash.nchain();
  node_["buckets"] = sysvhash.buckets();
  node_["chains"]  = sysvhash.chains();
}



} // namespace ELF
} // namespace LIEF

