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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DynamicSymbolCommand.hpp"

namespace LIEF {
namespace MachO {

DynamicSymbolCommand::DynamicSymbolCommand(void) :
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

DynamicSymbolCommand::DynamicSymbolCommand(const dysymtab_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},

  idx_local_symbol_{cmd->ilocalsym},
  nb_local_symbols_{cmd->nlocalsym},

  idx_external_define_symbol_{cmd->iextdefsym},
  nb_external_define_symbols_{cmd->nextdefsym},

  idx_undefined_symbol_{cmd->iundefsym},
  nb_undefined_symbols_{cmd->nundefsym},

  toc_offset_{cmd->tocoff},
  nb_toc_{cmd->ntoc},

  module_table_offset_{cmd->modtaboff},
  nb_module_table_{cmd->nmodtab},

  external_reference_symbol_offset_{cmd->extrefsymoff},
  nb_external_reference_symbols_{cmd->nextrefsyms},

  indirect_sym_offset_{cmd->indirectsymoff},
  nb_indirect_symbols_{cmd->nindirectsyms},

  external_relocation_offset_{cmd->extreloff},
  nb_external_relocations_{cmd->nextrel},

  local_relocation_offset_{cmd->locreloff},
  nb_local_relocations_{cmd->nlocrel}
{}



DynamicSymbolCommand& DynamicSymbolCommand::operator=(const DynamicSymbolCommand&) = default;

DynamicSymbolCommand::DynamicSymbolCommand(const DynamicSymbolCommand&) = default;

DynamicSymbolCommand::~DynamicSymbolCommand(void) = default;


uint32_t DynamicSymbolCommand::idx_local_symbol(void) const {
  return this->idx_local_symbol_;
}

uint32_t DynamicSymbolCommand::nb_local_symbols(void) const {
  return this->nb_local_symbols_;
}


uint32_t DynamicSymbolCommand::idx_external_define_symbol(void) const {
  return this->idx_external_define_symbol_;
}

uint32_t DynamicSymbolCommand::nb_external_define_symbols(void) const {
  return this->nb_external_define_symbols_;
}


uint32_t DynamicSymbolCommand::idx_undefined_symbol(void) const {
  return this->idx_undefined_symbol_;
}

uint32_t DynamicSymbolCommand::nb_undefined_symbols(void) const {
  return this->nb_undefined_symbols_;
}


uint32_t DynamicSymbolCommand::toc_offset(void) const {
  return this->toc_offset_;
}

uint32_t DynamicSymbolCommand::nb_toc(void) const {
  return this->nb_toc_;
}


uint32_t DynamicSymbolCommand::module_table_offset(void) const {
  return this->module_table_offset_;
}

uint32_t DynamicSymbolCommand::nb_module_table(void) const {
  return this->nb_module_table_;
}


uint32_t DynamicSymbolCommand::external_reference_symbol_offset(void) const {
  return this->external_reference_symbol_offset_;
}

uint32_t DynamicSymbolCommand::nb_external_reference_symbols(void) const {
  return this->nb_external_reference_symbols_;
}


uint32_t DynamicSymbolCommand::indirect_symbol_offset(void) const {
  return this->indirect_sym_offset_;
}

uint32_t DynamicSymbolCommand::nb_indirect_symbols(void) const {
  return this->nb_indirect_symbols_;
}


uint32_t DynamicSymbolCommand::external_relocation_offset(void) const {
  return this->external_relocation_offset_;
}

uint32_t DynamicSymbolCommand::nb_external_relocations(void) const {
  return this->nb_external_relocations_;
}


uint32_t DynamicSymbolCommand::local_relocation_offset(void) const {
  return this->local_relocation_offset_;
}

uint32_t DynamicSymbolCommand::nb_local_relocations(void) const {
  return this->nb_local_relocations_;
}


void DynamicSymbolCommand::idx_local_symbol(uint32_t value) {
  this->idx_local_symbol_ = value;
}
void DynamicSymbolCommand::nb_local_symbols(uint32_t value) {
  this->nb_local_symbols_ = value;
}

void DynamicSymbolCommand::idx_external_define_symbol(uint32_t value) {
  this->idx_external_define_symbol_ = value;
}
void DynamicSymbolCommand::nb_external_define_symbols(uint32_t value) {
  this->nb_external_define_symbols_ = value;
}

void DynamicSymbolCommand::idx_undefined_symbol(uint32_t value) {
  this->idx_undefined_symbol_ = value;
}

void DynamicSymbolCommand::nb_undefined_symbols(uint32_t value) {
  this->nb_undefined_symbols_ = value;
}

void DynamicSymbolCommand::toc_offset(uint32_t value) {
  this->toc_offset_ = value;
}

void DynamicSymbolCommand::nb_toc(uint32_t value) {
  this->nb_toc_ = value;
}

void DynamicSymbolCommand::module_table_offset(uint32_t value) {
  this->module_table_offset_ = value;
}

void DynamicSymbolCommand::nb_module_table(uint32_t value) {
  this->nb_module_table_ = value;
}

void DynamicSymbolCommand::external_reference_symbol_offset(uint32_t value) {
  this->external_reference_symbol_offset_ = value;
}

void DynamicSymbolCommand::nb_external_reference_symbols(uint32_t value) {
  this->nb_external_reference_symbols_ = value;
}

void DynamicSymbolCommand::indirect_symbol_offset(uint32_t value) {
  this->indirect_sym_offset_ = value;
}

void DynamicSymbolCommand::nb_indirect_symbols(uint32_t value) {
  this->nb_indirect_symbols_ = value;
}

void DynamicSymbolCommand::external_relocation_offset(uint32_t value) {
  this->external_relocation_offset_ = value;
}

void DynamicSymbolCommand::nb_external_relocations(uint32_t value) {
  this->nb_external_relocations_ = value;
}

void DynamicSymbolCommand::local_relocation_offset(uint32_t value) {
  this->local_relocation_offset_ = value;
}

void DynamicSymbolCommand::nb_local_relocations(uint32_t value) {
  this->nb_local_relocations_ = value;
}


void DynamicSymbolCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DynamicSymbolCommand::operator==(const DynamicSymbolCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DynamicSymbolCommand::operator!=(const DynamicSymbolCommand& rhs) const {
  return not (*this == rhs);
}


std::ostream& DynamicSymbolCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  static constexpr size_t WIDTH = 36;
  os << std::hex;
  os << std::left
     << std::setw(WIDTH) << "First local symbol index:"          << this->idx_local_symbol()
     << std::endl
     << std::setw(WIDTH) << "Number of local symbols:"           << this->nb_local_symbols()
     << std::endl
     << std::setw(WIDTH) << "External symbol index:"             << this->idx_external_define_symbol()
     << std::endl
     << std::setw(WIDTH) << "Number of external symbols:"        << this->nb_external_define_symbols()
     << std::endl
     << std::setw(WIDTH) << "Undefined symbol index:"            << this->idx_undefined_symbol()
     << std::endl
     << std::setw(WIDTH) << "Number of undefined symbols:"       << this->nb_undefined_symbols()
     << std::endl
     << std::setw(WIDTH) << "Table of content offset:"           << this->toc_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of entries in TOC:"          << this->nb_toc()
     << std::endl
     << std::setw(WIDTH) << "Module table offset:"               << this->module_table_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of entries in module table:" << this->nb_module_table()
     << std::endl
     << std::setw(WIDTH) << "External reference table offset:"   << this->external_reference_symbol_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of external reference:"      << this->nb_external_reference_symbols()
     << std::endl
     << std::setw(WIDTH) << "Indirect symbols offset:"           << this->indirect_symbol_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of indirect symbols:"        << this->nb_indirect_symbols()
     << std::endl
     << std::setw(WIDTH) << "External relocation offset:"        << this->external_relocation_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of external relocations:"    << this->nb_external_relocations()
     << std::endl
     << std::setw(WIDTH) << "Local relocation offset:"           << this->local_relocation_offset()
     << std::endl
     << std::setw(WIDTH) << "Number of local relocations:"       << this->nb_local_relocations()
     << std::endl;

  return os;
}

}
}

