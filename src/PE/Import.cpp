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
#include <algorithm>
#include <iomanip>
#include <utility>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/PE/Import.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

Import::~Import() = default;

Import::Import() = default;
Import::Import(const Import& other) = default;


Import& Import::operator=(Import other) {
  swap(other);
  return *this;
}

void Import::swap(Import& other) {
  std::swap(entries_,                  other.entries_);
  std::swap(directory_,                other.directory_);
  std::swap(iat_directory_,            other.iat_directory_);
  std::swap(import_lookup_table_RVA_,  other.import_lookup_table_RVA_);
  std::swap(timedatestamp_,            other.timedatestamp_);
  std::swap(forwarder_chain_,          other.forwarder_chain_);
  std::swap(name_RVA_,                 other.name_RVA_);
  std::swap(import_address_table_RVA_, other.import_address_table_RVA_);
  std::swap(name_,                     other.name_);
  std::swap(type_,                     other.type_);
}


Import::Import(const details::pe_import& import) :
  import_lookup_table_RVA_(import.ImportLookupTableRVA),
  timedatestamp_(import.TimeDateStamp),
  forwarder_chain_(import.ForwarderChain),
  name_RVA_(import.NameRVA),
  import_address_table_RVA_(import.ImportAddressTableRVA)
{}


Import::Import(std::string name) :
  name_{std::move(name)}
{}


const ImportEntry* Import::get_entry(const std::string& name) const {
  const auto it_entry = std::find_if(std::begin(entries_), std::end(entries_),
      [&name] (const ImportEntry& entry) {
        return entry.name() == name;
      });
  if (it_entry == std::end(entries_)) {
    return nullptr;
  }
  return &*it_entry;
}

ImportEntry* Import::get_entry(const std::string& name) {
  return const_cast<ImportEntry*>(static_cast<const Import*>(this)->get_entry(name));
}

Import::it_entries Import::entries() {
  return entries_;
}


Import::it_const_entries Import::entries() const {
  return entries_;
}


uint32_t Import::import_address_table_rva() const {
  return import_address_table_RVA_;
}


uint32_t Import::import_lookup_table_rva() const {
  return import_lookup_table_RVA_;
}


result<uint32_t> Import::get_function_rva_from_iat(const std::string& function) const {
  const auto it_function = std::find_if(std::begin(entries_), std::end(entries_),
      [&function] (const ImportEntry& entry) {
        return entry.name() == function;
      });

  if (it_function == std::end(entries_)) {
    return make_error_code(lief_errors::not_found);
  }

  // Index of the function in the imported functions
  uint32_t idx = std::distance(std::begin(entries_), it_function);

  if (type_ == PE_TYPE::PE32) {
    return idx * sizeof(uint32_t);
  }
  return idx * sizeof(uint64_t);
}


const std::string& Import::name() const {
  return name_;
}

//std::string& Import::name() {
//  return const_cast<std::string&>(static_cast<const Import*>(this)->name());
//}

void Import::name(const std::string& name) {
  name_ = name;
}


const DataDirectory* Import::directory() const {
  return directory_;
}

DataDirectory* Import::directory() {
  return const_cast<DataDirectory*>(static_cast<const Import*>(this)->directory());
}


const DataDirectory* Import::iat_directory() const {
  return iat_directory_;
}

DataDirectory* Import::iat_directory() {
  return const_cast<DataDirectory*>(static_cast<const Import*>(this)->iat_directory());
}


void Import::import_lookup_table_rva(uint32_t rva) {
  import_lookup_table_RVA_ = rva;
}


void Import::import_address_table_rva(uint32_t rva) {
  import_address_table_RVA_ = rva;
}

ImportEntry& Import::add_entry(const ImportEntry& entry) {
  entries_.push_back(entry);
  return entries_.back();
}


ImportEntry& Import::add_entry(const std::string& name) {
  entries_.emplace_back(name);
  return entries_.back();
}

uint32_t Import::forwarder_chain() const {
  return forwarder_chain_;
}

uint32_t Import::timedatestamp() const {
  return timedatestamp_;
}

void Import::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Import::operator==(const Import& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Import::operator!=(const Import& rhs) const {
  return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Import& entry) {
  os << std::hex;
  os << std::left
     << std::setw(20) << entry.name()
     << std::setw(10) << entry.import_lookup_table_rva()
     << std::setw(10) << entry.import_address_table_rva()
     << std::setw(10) << entry.forwarder_chain()
     << std::setw(10) << entry.timedatestamp()
     << std::endl;

  for (const ImportEntry& functions: entry.entries()) {
    os << "\t - " << functions << std::endl;
  }

  return os;
}
}
}
