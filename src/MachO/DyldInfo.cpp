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

namespace LIEF {
namespace MachO {

DyldInfo::DyldInfo(void) = default;
DyldInfo& DyldInfo::operator=(const DyldInfo&) = default;
DyldInfo::DyldInfo(const DyldInfo&) = default;
DyldInfo::~DyldInfo(void) = default;

DyldInfo::DyldInfo(const dyld_info_command *dyld_info_cmd) :
  rebase_{dyld_info_cmd->rebase_off, dyld_info_cmd->rebase_size},
  bind_{dyld_info_cmd->bind_off, dyld_info_cmd->bind_size},
  weak_bind_{dyld_info_cmd->weak_bind_off, dyld_info_cmd->weak_bind_size},
  lazy_bind_{dyld_info_cmd->lazy_bind_off, dyld_info_cmd->lazy_bind_size},
  export_{dyld_info_cmd->export_off, dyld_info_cmd->export_size}
{
  this->command_ = static_cast<LOAD_COMMAND_TYPES>(dyld_info_cmd->cmd);
  this->size_    = dyld_info_cmd->cmdsize;
}

const DyldInfo::info_t& DyldInfo::rebase(void) const {
  return this->rebase_;
}

const DyldInfo::info_t& DyldInfo::bind(void) const {
  return this->bind_;
}

const DyldInfo::info_t& DyldInfo::weak_bind(void) const {
  return this->weak_bind_;
}

const DyldInfo::info_t& DyldInfo::lazy_bind(void) const {
  return this->lazy_bind_;
}

const DyldInfo::info_t& DyldInfo::export_info(void) const {
  return this->export_;
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
  return os;
}


}
}
