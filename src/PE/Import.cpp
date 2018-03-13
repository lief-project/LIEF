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
#include <algorithm>
#include <iomanip>

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/Import.hpp"

namespace LIEF {
namespace PE {

Import::~Import(void) = default;

Import::Import(const Import& other) :
  Object{other},
  entries_{other.entries_},
  directory_{nullptr},
  iat_directory_{nullptr},
  import_lookup_table_RVA_{other.import_lookup_table_RVA_},
  timedatestamp_{other.timedatestamp_},
  forwarder_chain_{other.forwarder_chain_},
  name_RVA_{other.name_RVA_},
  import_address_table_RVA_{other.import_address_table_RVA_},
  name_{other.name_},
  type_{other.type_}
{}


Import& Import::operator=(Import other) {
  this->swap(other);
  return *this;
}

void Import::swap(Import& other) {
  std::swap(this->entries_,                  other.entries_);
  std::swap(this->directory_,                other.directory_);
  std::swap(this->iat_directory_,            other.iat_directory_);
  std::swap(this->import_lookup_table_RVA_,  other.import_lookup_table_RVA_);
  std::swap(this->timedatestamp_,            other.timedatestamp_);
  std::swap(this->forwarder_chain_,          other.forwarder_chain_);
  std::swap(this->name_RVA_,                 other.name_RVA_);
  std::swap(this->import_address_table_RVA_, other.import_address_table_RVA_);
  std::swap(this->name_,                     other.name_);
  std::swap(this->type_,                     other.type_);
}

Import::Import(void) :
  entries_{},
  directory_{nullptr},
  iat_directory_{nullptr},
  import_lookup_table_RVA_{0},
  timedatestamp_{0},
  forwarder_chain_{0},
  name_RVA_{0},
  import_address_table_RVA_{0},
  name_{""},
  type_{PE_TYPE::PE32} // Arbitrary value

{}

Import::Import(const pe_import *import) :
  entries_{},
  directory_{nullptr},
  iat_directory_{nullptr},
  import_lookup_table_RVA_(import->ImportLookupTableRVA),
  timedatestamp_(import->TimeDateStamp),
  forwarder_chain_(import->ForwarderChain),
  name_RVA_(import->NameRVA),
  import_address_table_RVA_(import->ImportAddressTableRVA),
  name_{""},
  type_{PE_TYPE::PE32} // Arbitrary value
{}


Import::Import(const std::string& name) :
  entries_{},
  directory_{nullptr},
  iat_directory_{nullptr},
  import_lookup_table_RVA_{0},
  timedatestamp_{0},
  forwarder_chain_{0},
  name_RVA_{0},
  import_address_table_RVA_{0},
  name_{name},
  type_{PE_TYPE::PE32} // Arbitrary value
{}


const ImportEntry& Import::get_entry(const std::string& name) const {
  auto&& it_entry = std::find_if(
      std::begin(this->entries_),
      std::end(this->entries_),
      [&name] (const ImportEntry& entry) {
        return entry.name() == name;
      });
  if (it_entry == std::end(this->entries_)) {
    throw LIEF::not_found("Unable to find the entry '" + name + "'.");
  }
  return *it_entry;
}

ImportEntry& Import::get_entry(const std::string& name) {
  return const_cast<ImportEntry&>(static_cast<const Import*>(this)->get_entry(name));
}

it_import_entries Import::entries(void) {
  return {this->entries_};
}


it_const_import_entries Import::entries(void) const {
  return {this->entries_};
}


uint32_t Import::import_address_table_rva(void) const {
  return this->import_address_table_RVA_;
}


uint32_t Import::import_lookup_table_rva(void) const {
  return this->import_lookup_table_RVA_;
}


uint32_t Import::get_function_rva_from_iat(const std::string& function) const {
  auto&& it_function = std::find_if(
      std::begin(this->entries_),
      std::end(this->entries_),
      [&function] (const ImportEntry& entry)
      {
        return entry.name() == function;
      });

  if (it_function == std::end(this->entries_)) {
    throw LIEF::not_found("No such function ('" + function + "')");
  }

  // Index of the function in the imported functions
  uint32_t idx = std::distance(std::begin(this->entries_), it_function);

  if (this->type_ == PE_TYPE::PE32) {
    return idx * sizeof(uint32_t);
  } else {
    return idx * sizeof(uint64_t);
  }
}


const std::string& Import::name(void) const {
  return this->name_;
}

//std::string& Import::name(void) {
//  return const_cast<std::string&>(static_cast<const Import*>(this)->name());
//}

void Import::name(const std::string& name) {
  this->name_ = name;
}


const DataDirectory& Import::directory(void) const {
  if (this->directory_ != nullptr) {
    return *this->directory_;
  } else {
    throw not_found("Unable to find the Data Directory");
  }
}

DataDirectory& Import::directory(void) {
  return const_cast<DataDirectory&>(static_cast<const Import*>(this)->directory());
}


const DataDirectory& Import::iat_directory(void) const {
  if (this->iat_directory_ != nullptr) {
    return *this->iat_directory_;
  } else {
    throw not_found("Unable to find the IAT Data Directory");
  }
}

DataDirectory& Import::iat_directory(void) {
  return const_cast<DataDirectory&>(static_cast<const Import*>(this)->iat_directory());
}


void Import::import_lookup_table_rva(uint32_t rva) {
  this->import_lookup_table_RVA_ = rva;
}


void Import::import_address_table_rva(uint32_t rva) {
  this->import_address_table_RVA_ = rva;
}

ImportEntry& Import::add_entry(const ImportEntry& entry) {
  this->entries_.push_back(entry);
  return this->entries_.back();
}


ImportEntry& Import::add_entry(const std::string& name) {
  this->entries_.emplace_back(name);
  return this->entries_.back();
}

uint32_t Import::forwarder_chain(void) const {
  return this->forwarder_chain_;
}

uint32_t Import::timedatestamp(void) const {
  return this->timedatestamp_;
}

void Import::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Import::operator==(const Import& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Import::operator!=(const Import& rhs) const {
  return not (*this == rhs);
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
