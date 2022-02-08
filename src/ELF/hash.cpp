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

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF.hpp"

namespace LIEF {
namespace ELF {

Hash::~Hash() = default;

size_t Hash::hash(const Object& obj) {
  return LIEF::Hash::hash<LIEF::ELF::Hash>(obj);
}


void Hash::visit(const Binary& binary) {
  process(binary.header());

  process(std::begin(binary.sections()), std::end(binary.sections()));
  process(std::begin(binary.segments()), std::end(binary.segments()));
  process(std::begin(binary.dynamic_entries()), std::end(binary.dynamic_entries()));
  process(std::begin(binary.dynamic_symbols()), std::end(binary.dynamic_symbols()));
  process(std::begin(binary.static_symbols()), std::end(binary.static_symbols()));
  process(std::begin(binary.relocations()), std::end(binary.relocations()));
  process(std::begin(binary.notes()), std::end(binary.notes()));

  if (binary.use_gnu_hash()) {
    process(*binary.gnu_hash());
  }

  if (binary.use_sysv_hash()) {
    process(*binary.sysv_hash());
  }

  if (binary.has_interpreter()) {
    process(binary.interpreter());
  }

}


void Hash::visit(const Header& header) {
  process(header.file_type());
  process(header.entrypoint());
  process(header.program_headers_offset());
  process(header.section_headers_offset());
  process(header.processor_flag());
  process(header.header_size());
  process(header.program_header_size());
  process(header.numberof_segments());
  process(header.section_header_size());
  process(header.numberof_sections());
  process(header.section_name_table_idx());
  process(header.identity());
}


void Hash::visit(const Section& section) {
  process(section.name());
  process(section.size());
  process(section.content());
  process(section.virtual_address());
  process(section.offset());

  process(section.type());
  process(section.size());
  process(section.alignment());
  process(section.information());
  process(section.entry_size());
  process(section.link());
}

void Hash::visit(const Segment& segment) {
  process(segment.type());
  process(segment.flags());
  process(segment.file_offset());
  process(segment.virtual_address());
  process(segment.physical_address());
  process(segment.physical_size());
  process(segment.virtual_size());
  process(segment.alignment());
  process(segment.content());
}

void Hash::visit(const DynamicEntry& entry) {
  process(entry.tag());
  process(entry.value());
}


void Hash::visit(const DynamicEntryArray& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  process(entry.array());
}


void Hash::visit(const DynamicEntryLibrary& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  process(entry.name());
}


void Hash::visit(const DynamicEntryRpath& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  process(entry.rpath());
}


void Hash::visit(const DynamicEntryRunPath& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  process(entry.runpath());
}


void Hash::visit(const DynamicSharedObject& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  process(entry.name());
}


void Hash::visit(const DynamicEntryFlags& entry) {
  visit(static_cast<const DynamicEntry&>(entry));
  process(entry.flags());
}

void Hash::visit(const Symbol& symbol) {
  process(symbol.name());
  process(symbol.value());
  process(symbol.size());

  process(symbol.type());
  process(symbol.binding());
  process(symbol.information());
  process(symbol.other());
  process(symbol.section_idx());
  process(symbol.visibility());
  process(symbol.value());
  const SymbolVersion* symver = symbol.symbol_version();
  if (symver != nullptr) {
    process(*symver);
  }
}

void Hash::visit(const Relocation& relocation) {
  process(relocation.address());
  process(relocation.size());

  process(relocation.addend());
  process(relocation.type());
  process(relocation.architecture());
  process(relocation.purpose());

  const Symbol* sym = relocation.symbol();
  if (sym != nullptr) {
    process(*sym);
  }

}

void Hash::visit(const SymbolVersion& sv) {
  process(sv.value());
  if (sv.has_auxiliary_version()) {
    process(*sv.symbol_version_auxiliary());
  }
}

void Hash::visit(const SymbolVersionRequirement& svr) {
  process(svr.version());
  process(svr.name());
  process(std::begin(svr.auxiliary_symbols()), std::end(svr.auxiliary_symbols()));
}

void Hash::visit(const SymbolVersionDefinition& svd) {
  process(svd.version());
  process(svd.flags());
  process(svd.ndx());
  process(svd.hash());
}

void Hash::visit(const SymbolVersionAux& sv) {
  process(sv.name());
}

void Hash::visit(const SymbolVersionAuxRequirement& svar) {
  visit(static_cast<const SymbolVersionAux&>(svar));
  process(svar.hash());
  process(svar.flags());
  process(svar.other());
}

void Hash::visit(const Note& note) {
  process(note.name());
  process(note.type());
  process(note.description());
}

void Hash::visit(const NoteDetails& details) {
  process(details.description());
}

void Hash::visit(const AndroidNote& note) {
  visit(static_cast<const NoteDetails&>(note));
}

void Hash::visit(const NoteAbi& note) {
  visit(static_cast<const NoteDetails&>(note));
}

void Hash::visit(const CorePrPsInfo& pinfo) {
  process(pinfo.file_name());
  process(pinfo.flags());
  process(pinfo.uid());
  process(pinfo.gid());
  process(pinfo.pid());
  process(pinfo.ppid());
  process(pinfo.pgrp());
  process(pinfo.sid());
}

void Hash::visit(const CorePrStatus& pstatus) {
  process(pstatus.siginfo().si_code);
  process(pstatus.siginfo().si_errno);
  process(pstatus.siginfo().si_signo);

  process(pstatus.current_sig());
  process(pstatus.sigpend());
  process(pstatus.sighold());
  process(pstatus.pid());
  process(pstatus.ppid());
  process(pstatus.pgrp());
  process(pstatus.sid());

  process(pstatus.utime().sec);
  process(pstatus.utime().usec);

  process(pstatus.stime().sec);
  process(pstatus.stime().usec);

  process(pstatus.cutime().sec);
  process(pstatus.cutime().usec);

  process(pstatus.cstime().sec);
  process(pstatus.cstime().usec);

  for (const CorePrStatus::reg_context_t::value_type& val : pstatus.reg_context()) {
    process(val.first);  // Register
    process(val.second); // Value
  }
}

void Hash::visit(const CoreAuxv& auxv) {
  for (const CoreAuxv::val_context_t::value_type& val : auxv.values()) {
    process(val.first);  // Type
    process(val.second); // Value
  }
}

void Hash::visit(const CoreSigInfo& siginfo) {
  process(siginfo.signo());
  process(siginfo.sigcode());
  process(siginfo.sigerrno());
}

void Hash::visit(const CoreFile& file) {
  process(file.count());
  for (const CoreFileEntry& entry : file.files()) {
    process(entry.start);
    process(entry.end);
    process(entry.file_ofs);
    process(entry.path);
  }
}

void Hash::visit(const GnuHash& gnuhash) {
  process(gnuhash.nb_buckets());
  process(gnuhash.symbol_index());
  process(gnuhash.shift2());
  process(gnuhash.maskwords());
  process(gnuhash.bloom_filters());
  process(gnuhash.buckets());
  process(gnuhash.hash_values());
}

void Hash::visit(const SysvHash& sysvhash) {
  process(sysvhash.nbucket());
  process(sysvhash.nchain());
  process(sysvhash.buckets());
  process(sysvhash.chains());
}



} // namespace ELF
} // namespace LIEF

