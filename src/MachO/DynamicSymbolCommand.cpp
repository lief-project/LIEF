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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

DynamicSymbolCommand::DynamicSymbolCommand() :
  LoadCommand::LoadCommand{LOAD_COMMAND_TYPES::LC_DYSYMTAB, 0},
  idx_local_symbol_{0},
  nb_local_symbols_{0},

  idx_external_define_symbol_{0},
  nb_external_define_symbols_{0},

  idx_undefined_symbol_{0},
  nb_undefined_symbols_{0},

  toc_offset_{0},
  nb_toc_{0},

  module_table_offset_{0},
  nb_module_table_{0},

  external_reference_symbol_offset_{0},
  nb_external_reference_symbols_{0},

  indirect_sym_offset_{0},
  nb_indirect_symbols_{0},

  external_relocation_offset_{0},
  nb_external_relocations_{0},

  local_relocation_offset_{0},
  nb_local_relocations_{0}
{}

DynamicSymbolCommand::DynamicSymbolCommand(const details::dysymtab_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},

  idx_local_symbol_{cmd.ilocalsym},
  nb_local_symbols_{cmd.nlocalsym},

  idx_external_define_symbol_{cmd.iextdefsym},
  nb_external_define_symbols_{cmd.nextdefsym},

  idx_undefined_symbol_{cmd.iundefsym},
  nb_undefined_symbols_{cmd.nundefsym},

  toc_offset_{cmd.tocoff},
  nb_toc_{cmd.ntoc},

  module_table_offset_{cmd.modtaboff},
  nb_module_table_{cmd.nmodtab},

  external_reference_symbol_offset_{cmd.extrefsymoff},
  nb_external_reference_symbols_{cmd.nextrefsyms},

  indirect_sym_offset_{cmd.indirectsymoff},
  nb_indirect_symbols_{cmd.nindirectsyms},

  external_relocation_offset_{cmd.extreloff},
  nb_external_relocations_{cmd.nextrel},

  local_relocation_offset_{cmd.locreloff},
  nb_local_relocations_{cmd.nlocrel}
{}



DynamicSymbolCommand& DynamicSymbolCommand::operator=(const DynamicSymbolCommand&) = default;

DynamicSymbolCommand::DynamicSymbolCommand(const DynamicSymbolCommand&) = default;

DynamicSymbolCommand::~DynamicSymbolCommand() = default;

DynamicSymbolCommand* DynamicSymbolCommand::clone() const {
  return new DynamicSymbolCommand(*this);
}


uint32_t DynamicSymbolCommand::idx_local_symbol() const {
  return idx_local_symbol_;
}

uint32_t DynamicSymbolCommand::nb_local_symbols() const {
  return nb_local_symbols_;
}


uint32_t DynamicSymbolCommand::idx_external_define_symbol() const {
  return idx_external_define_symbol_;
}

uint32_t DynamicSymbolCommand::nb_external_define_symbols() const {
  return nb_external_define_symbols_;
}


uint32_t DynamicSymbolCommand::idx_undefined_symbol() const {
  return idx_undefined_symbol_;
}

uint32_t DynamicSymbolCommand::nb_undefined_symbols() const {
  return nb_undefined_symbols_;
}


uint32_t DynamicSymbolCommand::toc_offset() const {
  return toc_offset_;
}

uint32_t DynamicSymbolCommand::nb_toc() const {
  return nb_toc_;
}


uint32_t DynamicSymbolCommand::module_table_offset() const {
  return module_table_offset_;
}

uint32_t DynamicSymbolCommand::nb_module_table() const {
  return nb_module_table_;
}


uint32_t DynamicSymbolCommand::external_reference_symbol_offset() const {
  return external_reference_symbol_offset_;
}

uint32_t DynamicSymbolCommand::nb_external_reference_symbols() const {
  return nb_external_reference_symbols_;
}


uint32_t DynamicSymbolCommand::indirect_symbol_offset() const {
  return indirect_sym_offset_;
}

uint32_t DynamicSymbolCommand::nb_indirect_symbols() const {
  return nb_indirect_symbols_;
}


uint32_t DynamicSymbolCommand::external_relocation_offset() const {
  return external_relocation_offset_;
}

uint32_t DynamicSymbolCommand::nb_external_relocations() const {
  return nb_external_relocations_;
}


uint32_t DynamicSymbolCommand::local_relocation_offset() const {
  return local_relocation_offset_;
}

uint32_t DynamicSymbolCommand::nb_local_relocations() const {
  return nb_local_relocations_;
}


void DynamicSymbolCommand::idx_local_symbol(uint32_t value) {
  idx_local_symbol_ = value;
}
void DynamicSymbolCommand::nb_local_symbols(uint32_t value) {
  nb_local_symbols_ = value;
}

void DynamicSymbolCommand::idx_external_define_symbol(uint32_t value) {
  idx_external_define_symbol_ = value;
}
void DynamicSymbolCommand::nb_external_define_symbols(uint32_t value) {
  nb_external_define_symbols_ = value;
}

void DynamicSymbolCommand::idx_undefined_symbol(uint32_t value) {
  idx_undefined_symbol_ = value;
}

void DynamicSymbolCommand::nb_undefined_symbols(uint32_t value) {
  nb_undefined_symbols_ = value;
}

void DynamicSymbolCommand::toc_offset(uint32_t value) {
  toc_offset_ = value;
}

void DynamicSymbolCommand::nb_toc(uint32_t value) {
  nb_toc_ = value;
}

void DynamicSymbolCommand::module_table_offset(uint32_t value) {
  module_table_offset_ = value;
}

void DynamicSymbolCommand::nb_module_table(uint32_t value) {
  nb_module_table_ = value;
}

void DynamicSymbolCommand::external_reference_symbol_offset(uint32_t value) {
  external_reference_symbol_offset_ = value;
}

void DynamicSymbolCommand::nb_external_reference_symbols(uint32_t value) {
  nb_external_reference_symbols_ = value;
}

void DynamicSymbolCommand::indirect_symbol_offset(uint32_t value) {
  indirect_sym_offset_ = value;
}

void DynamicSymbolCommand::nb_indirect_symbols(uint32_t value) {
  nb_indirect_symbols_ = value;
}

void DynamicSymbolCommand::external_relocation_offset(uint32_t value) {
  external_relocation_offset_ = value;
}

void DynamicSymbolCommand::nb_external_relocations(uint32_t value) {
  nb_external_relocations_ = value;
}

void DynamicSymbolCommand::local_relocation_offset(uint32_t value) {
  local_relocation_offset_ = value;
}

void DynamicSymbolCommand::nb_local_relocations(uint32_t value) {
  nb_local_relocations_ = value;
}


void DynamicSymbolCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DynamicSymbolCommand::operator==(const DynamicSymbolCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DynamicSymbolCommand::operator!=(const DynamicSymbolCommand& rhs) const {
  return !(*this == rhs);
}

bool DynamicSymbolCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_DYSYMTAB;
}

std::ostream& DynamicSymbolCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  static constexpr size_t WIDTH = 36;
  os << std::hex;
  os << std::left
     << std::setw(WIDTH) << "First local symbol index:"          << idx_local_symbol()
     << std::endl
     << std::setw(WIDTH) << "Number of local symbols:"           << nb_local_symbols()
     << std::endl
     << std::setw(WIDTH) << "External symbol index:"             << idx_external_define_symbol()
     << std::endl
     << std::setw(WIDTH) << "Number of external symbols:"        << nb_external_define_symbols()
     << std::endl
     << std::setw(WIDTH) << "Undefined symbol index:"            << idx_undefined_symbol()
     << std::endl
     << std::setw(WIDTH) << "Number of undefined symbols:"       << nb_undefined_symbols()
     << std::endl
     << std::setw(WIDTH) << "Table of content offset:"           << toc_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of entries in TOC:"          << nb_toc()
     << std::endl
     << std::setw(WIDTH) << "Module table offset:"               << module_table_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of entries in module table:" << nb_module_table()
     << std::endl
     << std::setw(WIDTH) << "External reference table offset:"   << external_reference_symbol_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of external reference:"      << nb_external_reference_symbols()
     << std::endl
     << std::setw(WIDTH) << "Indirect symbols offset:"           << indirect_symbol_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of indirect symbols:"        << nb_indirect_symbols()
     << std::endl
     << std::setw(WIDTH) << "External relocation offset:"        << external_relocation_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of external relocations:"    << nb_external_relocations()
     << std::endl
     << std::setw(WIDTH) << "Local relocation offset:"           << local_relocation_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of local relocations:"       << nb_local_relocations()
     << std::endl;

  return os;
}

}
}

