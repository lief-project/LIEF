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
#include "LIEF/MachO.hpp"

namespace LIEF {

// MachO part
// ----------

void Visitor::visit(const MachO::Binary& binary) {
  binary.accept(*this);
}

void Visitor::visit(const MachO::Header& header) {
  header.accept(*this);
}

void Visitor::visit(const MachO::LoadCommand& load_command) {
  load_command.accept(*this);
}

void Visitor::visit(const MachO::UUIDCommand& uuid_command) {
  uuid_command.accept(*this);
}

void Visitor::visit(const MachO::SymbolCommand& symbol_command) {
  symbol_command.accept(*this);
}

void Visitor::visit(const MachO::SegmentCommand& segment_command) {
  segment_command.accept(*this);
}

void Visitor::visit(const MachO::Section& section) {
  section.accept(*this);
}

void Visitor::visit(const MachO::MainCommand& main_command) {
  main_command.accept(*this);
}

void Visitor::visit(const MachO::DynamicSymbolCommand& dyn_sym_cmd) {
  dyn_sym_cmd.accept(*this);
}

void Visitor::visit(const MachO::DylinkerCommand& dylinker_command) {
  dylinker_command.accept(*this);
}

void Visitor::visit(const MachO::DylibCommand& dylib_command) {
  dylib_command.accept(*this);
}

void Visitor::visit(const MachO::Symbol& symbol) {
  symbol.accept(*this);
}

void Visitor::visit(const MachO::Relocation& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const MachO::RelocationObject& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const MachO::RelocationDyld& relocation) {
  relocation.accept(*this);
}

void Visitor::visit(const MachO::BindingInfo& binding_info) {
  binding_info.accept(*this);
}

void Visitor::visit(const MachO::ExportInfo& export_info) {
  export_info.accept(*this);
}

void Visitor::visit(const MachO::ThreadCommand& thread) {
  thread.accept(*this);
}

}
