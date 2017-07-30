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
#include <numeric>
#include <iomanip>

#include "LIEF/visitors/Hash.hpp"

#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

namespace LIEF {
namespace MachO {

DyldInfo::DyldInfo(void) = default;
DyldInfo& DyldInfo::operator=(const DyldInfo&) = default;
DyldInfo::DyldInfo(const DyldInfo&) = default;

DyldInfo::~DyldInfo(void) {
  for (BindingInfo* binfo : this->binding_info_) {
    delete binfo;
  }

  for (ExportInfo* einfo : this->export_info_) {
    delete einfo;
  }

}

DyldInfo::DyldInfo(const dyld_info_command *dyld_info_cmd) :
  rebase_{dyld_info_cmd->rebase_off, dyld_info_cmd->rebase_size},
  rebase_opcodes_{},
  bind_{dyld_info_cmd->bind_off, dyld_info_cmd->bind_size},
  bind_opcodes_{},
  weak_bind_{dyld_info_cmd->weak_bind_off, dyld_info_cmd->weak_bind_size},
  weak_bind_opcodes_{},
  lazy_bind_{dyld_info_cmd->lazy_bind_off, dyld_info_cmd->lazy_bind_size},
  lazy_bind_opcodes_{},
  export_{dyld_info_cmd->export_off, dyld_info_cmd->export_size},
  export_trie_{},
  export_info_{},
  binding_info_{}
{
  this->command_ = static_cast<LOAD_COMMAND_TYPES>(dyld_info_cmd->cmd);
  this->size_    = dyld_info_cmd->cmdsize;
}


// Rebase
// ======
const DyldInfo::info_t& DyldInfo::rebase(void) const {
  return this->rebase_;
}

const buffer_t& DyldInfo::rebase_opcodes(void) const {
  return this->rebase_opcodes_;
}

buffer_t& DyldInfo::rebase_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->rebase_opcodes());
}

void DyldInfo::rebase_opcodes(const buffer_t& raw) {
  this->rebase_opcodes_ = raw;
}


// Binding
// =======

it_binding_info DyldInfo::bindings(void) {
  return this->binding_info_;
}

it_const_binding_info DyldInfo::bindings(void) const {
  return this->binding_info_;
}

const DyldInfo::info_t& DyldInfo::bind(void) const {
  return this->bind_;
}

const buffer_t& DyldInfo::bind_opcodes(void) const {
  return this->bind_opcodes_;
}

buffer_t& DyldInfo::bind_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->bind_opcodes());
}

void DyldInfo::bind_opcodes(const buffer_t& raw) {
  this->bind_opcodes_ = raw;
}

// Weak Binding
// ============
const DyldInfo::info_t& DyldInfo::weak_bind(void) const {
  return this->weak_bind_;
}

const buffer_t& DyldInfo::weak_bind_opcodes(void) const {
  return this->weak_bind_opcodes_;
}

buffer_t& DyldInfo::weak_bind_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->weak_bind_opcodes());
}

void DyldInfo::weak_bind_opcodes(const buffer_t& raw) {
  this->weak_bind_opcodes_ = raw;
}

// Lazy Binding
// ============
const DyldInfo::info_t& DyldInfo::lazy_bind(void) const {
  return this->lazy_bind_;
}

const buffer_t& DyldInfo::lazy_bind_opcodes(void) const {
  return this->lazy_bind_opcodes_;
}

buffer_t& DyldInfo::lazy_bind_opcodes(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->lazy_bind_opcodes());
}

void DyldInfo::lazy_bind_opcodes(const buffer_t& raw) {
  this->lazy_bind_opcodes_ = raw;
}

// Export Info
// ===========
it_export_info DyldInfo::exports(void) {
  return this->export_info_;
}

it_const_export_info DyldInfo::exports(void) const {
  return this->export_info_;
}

const DyldInfo::info_t& DyldInfo::export_info(void) const {
  return this->export_;
}

const buffer_t& DyldInfo::export_trie(void) const {
  return this->export_trie_;
}

buffer_t& DyldInfo::export_trie(void) {
  return const_cast<buffer_t&>(static_cast<const DyldInfo*>(this)->export_trie());
}

void DyldInfo::export_trie(const buffer_t& raw) {
  this->export_trie_ = raw;
}


void DyldInfo::rebase(const DyldInfo::info_t& info) {
  this->rebase_ = info;
}

void DyldInfo::bind(const DyldInfo::info_t& info) {
  this->bind_ = info;
}

void DyldInfo::weak_bind(const DyldInfo::info_t& info) {
  this->weak_bind_ = info;
}

void DyldInfo::lazy_bind(const DyldInfo::info_t& info) {
  this->lazy_bind_ = info;
}

void DyldInfo::export_info(const DyldInfo::info_t& info) {
  this->export_ = info;
}



void DyldInfo::set_rebase_offset(uint32_t offset) {
  this->rebase_ = {offset, std::get<1>(this->rebase())};
}
void DyldInfo::set_rebase_size(uint32_t size) {
  this->rebase_ = {std::get<0>(this->rebase()), size};
}


void DyldInfo::set_bind_offset(uint32_t offset) {
  this->bind_ = {offset, std::get<1>(this->bind())};
}
void DyldInfo::set_bind_size(uint32_t size) {
  this->bind_ = {std::get<0>(this->bind()), size};
}


void DyldInfo::set_weak_bind_offset(uint32_t offset) {
  this->weak_bind_ = {offset, std::get<1>(this->weak_bind())};
}
void DyldInfo::set_weak_bind_size(uint32_t size) {
  this->weak_bind_ = {std::get<0>(this->weak_bind()), size};
}


void DyldInfo::set_lazy_bind_offset(uint32_t offset) {
  this->lazy_bind_ = {offset, std::get<1>(this->lazy_bind())};
}
void DyldInfo::set_lazy_bind_size(uint32_t size) {
  this->lazy_bind_ = {std::get<0>(this->lazy_bind()), size};
}


void DyldInfo::set_export_offset(uint32_t offset) {
  this->export_ = {offset, std::get<1>(this->export_info())};
}
void DyldInfo::set_export_size(uint32_t size) {
  this->export_ = {std::get<0>(this->export_info()), size};
}

void DyldInfo::accept(Visitor& visitor) const {
  LoadCommand::accept(visitor);
  visitor.visit(this->rebase());
  visitor.visit(this->bind());
  visitor.visit(this->weak_bind());
  visitor.visit(this->lazy_bind());
  visitor.visit(this->export_info());

  for (const BindingInfo& binfo : this->bindings()) {
    visitor(binfo);
  }


  for (const ExportInfo& einfo : this->exports()) {
    visitor(einfo);
  }
}


bool DyldInfo::operator==(const DyldInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DyldInfo::operator!=(const DyldInfo& rhs) const {
  return not (*this == rhs);
}


std::ostream& DyldInfo::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex << std::left;
  os << std::setw(11) << "Type "       << std::setw(10) << "Offset" << "Size" << std::endl;
  os << std::setw(11) << "Rebase: "    << std::setw(10) << std::get<0>(this->rebase())      << std::get<1>(this->rebase())      << std::endl;
  os << std::setw(11) << "Bind: "      << std::setw(10) << std::get<0>(this->bind())        << std::get<1>(this->bind())        << std::endl;
  os << std::setw(11) << "Weak bind: " << std::setw(10) << std::get<0>(this->weak_bind())   << std::get<1>(this->weak_bind())   << std::endl;
  os << std::setw(11) << "Lazy bind: " << std::setw(10) << std::get<0>(this->lazy_bind())   << std::get<1>(this->lazy_bind())   << std::endl;
  os << std::setw(11) << "Export: "    << std::setw(10) << std::get<0>(this->export_info()) << std::get<1>(this->export_info()) << std::endl;

  it_const_binding_info bindings = this->bindings();
  for (size_t i = 0; i < bindings.size(); ++i) {
    os << "Binding Info #" << std::dec << i << std::endl;
    os << "================" << std::endl;
    os << bindings[i] << std::endl;
  }


  it_const_export_info exports = this->exports();
  for (size_t i = 0; i < exports.size(); ++i) {
    os << "Export Info #" << std::dec << i << std::endl;
    os << "==============" << std::endl;
    os << exports[i] << std::endl;
  }
  return os;
}


}
}
