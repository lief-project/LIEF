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
#include "LIEF/Visitor.hpp"
#include "LIEF/ELF.hpp"

namespace LIEF {

// ELF part
// --------
void Visitor::visit(const ELF::Binary& binary) {
  binary.accept(*this);
}

void Visitor::visit(const ELF::Header& header) {
  header.accept(*this);
}

void Visitor::visit(const ELF::Section& section) {
  section.accept(*this);
}

void Visitor::visit(const ELF::Segment& segment) {
  segment.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntry& entry) {
  entry.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryArray& array) {
  array.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryLibrary& library) {
  library.accept(*this);
}

void Visitor::visit(const ELF::DynamicSharedObject& shared) {
  shared.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryRunPath& runpath) {
  runpath.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryRpath& rpath) {
  rpath.accept(*this);
}

void Visitor::visit(const ELF::DynamicEntryFlags& flags) {
  flags.accept(*this);
}

void Visitor::visit(const ELF::Symbol& symbol) {
  symbol.accept(*this);
}

void Visitor::visit(const ELF::Relocation& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersion& sv) {
  sv.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionRequirement& svr) {
  svr.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionDefinition& svd) {
  svd.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionAux& sva) {
  sva.accept(*this);
}

void Visitor::visit(const ELF::SymbolVersionAuxRequirement& svar) {
  svar.accept(*this);
}

void Visitor::visit(const ELF::Note& note) {
  note.accept(*this);
}

void Visitor::visit(const ELF::GnuHash& gnuhash) {
  gnuhash.accept(*this);
}

void Visitor::visit(const ELF::SysvHash& sysvhash) {
  sysvhash.accept(*this);
}

}
