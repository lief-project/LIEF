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
#include <sstream>

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Header.hpp"

namespace LIEF {
namespace PE {

Header::~Header(void) = default;
Header& Header::operator=(const Header&) = default;
Header::Header(const Header&) = default;

Header::Header(void) :
  machine_{MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN},
  numberOfSections_{0},
  timeDateStamp_{0},
  pointerToSymbolTable_{0},
  numberOfSymbols_{0},
  sizeOfOptionalHeader_{0},
  characteristics_{HEADER_CHARACTERISTICS::IMAGE_FILE_EXECUTABLE_IMAGE}
{
  std::copy(
      std::begin(PE_Magic),
      std::end(PE_Magic),
      std::begin(this->signature_));
}


Header::Header(const pe_header *header) :
  machine_(static_cast<MACHINE_TYPES>(header->Machine)),
  numberOfSections_(header->NumberOfSections),
  timeDateStamp_(header->TimeDateStamp),
  pointerToSymbolTable_(header->PointerToSymbolTable),
  numberOfSymbols_(header->NumberOfSymbols),
  sizeOfOptionalHeader_(header->SizeOfOptionalHeader),
  characteristics_(static_cast<HEADER_CHARACTERISTICS>(header->Characteristics))

{
  std::copy(
      reinterpret_cast<const uint8_t*>(header->signature),
      reinterpret_cast<const uint8_t*>(header->signature) + sizeof(PE_Magic),
      std::begin(this->signature_));
}

const Header::signature_t& Header::signature(void) const {
  return this->signature_;
}


MACHINE_TYPES Header::machine(void) const {
  return this->machine_;
}


uint16_t Header::numberof_sections(void) const {
  return this->numberOfSections_;
}


uint32_t Header::time_date_stamp(void) const {
  return this->timeDateStamp_;
}


uint32_t Header::pointerto_symbol_table(void) const {
  return this->pointerToSymbolTable_;
}


uint32_t Header::numberof_symbols(void) const {
  return this->numberOfSymbols_;
}


uint16_t Header::sizeof_optional_header(void) const {
  return this->sizeOfOptionalHeader_;
}


HEADER_CHARACTERISTICS Header::characteristics(void) const {
  return this->characteristics_;
}


bool Header::has_characteristic(HEADER_CHARACTERISTICS c) const {
  return (this->characteristics_ & c) != HEADER_CHARACTERISTICS::IMAGE_FILE_INVALID;
}


std::set<HEADER_CHARACTERISTICS> Header::characteristics_list(void) const {

  std::set<HEADER_CHARACTERISTICS> charac;
  std::copy_if(
      std::begin(header_characteristics_array),
      std::end(header_characteristics_array),
      std::inserter(charac, std::begin(charac)),
      std::bind(&Header::has_characteristic, this, std::placeholders::_1));

  return charac;
}

void Header::machine(MACHINE_TYPES type) {
  this->machine_ = type;
}


void Header::numberof_sections(uint16_t nbOfSections) {
  this->numberOfSections_ = nbOfSections;
}


void Header::time_date_stamp(uint32_t timestamp) {
  this->timeDateStamp_ = timestamp;
}


void Header::pointerto_symbol_table(uint32_t pointerToSymbol) {
  this->pointerToSymbolTable_ = pointerToSymbol;
}


void Header::numberof_symbols(uint32_t nbOfSymbols) {
  this->numberOfSymbols_ = nbOfSymbols;
}


void Header::sizeof_optional_header(uint16_t sizeOfOptionalHdr) {
  this->sizeOfOptionalHeader_ = sizeOfOptionalHdr;
}


void Header::characteristics(HEADER_CHARACTERISTICS characteristics) {
  this->characteristics_ = characteristics;
}


void Header::add_characteristic(HEADER_CHARACTERISTICS c) {
  this->characteristics_ |= c;
}


void Header::remove_characteristic(HEADER_CHARACTERISTICS c) {
  this->characteristics_ &= ~c;
}


void Header::signature(const Header::signature_t& sig) {
  std::copy(
      std::begin(sig),
      std::end(sig),
      std::begin(this->signature_));
}

void Header::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Header::operator==(const Header& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return not (*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const Header& entry) {


  const Header::signature_t& signature = entry.signature();
  std::stringstream ss;
  ss << std::hex;
  ss << static_cast<uint32_t>(signature[0]) << " ";
  ss << static_cast<uint32_t>(signature[1]) << " ";
  ss << static_cast<uint32_t>(signature[2]) << " ";
  ss << static_cast<uint32_t>(signature[3]) << " ";
  const std::string& signature_str = ss.str();

  const auto& chara = entry.characteristics_list();

  std::string chara_str = std::accumulate(
     std::begin(chara),
     std::end(chara), std::string{},
     [] (const std::string& a, HEADER_CHARACTERISTICS b) {
         return a.empty() ?
         to_string(b) :
         a + " - " + to_string(b);
     });
  os << std::hex;
  os << std::setw(30) << std::left << std::setfill(' ') << "Signature: "               << signature_str                               << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Machine: "                 << to_string(entry.machine_)       << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Number Of Sections: "      << entry.numberOfSections_                     << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Pointer To Symbol Table: " << entry.pointerToSymbolTable_                 << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Number Of Symbols: "       << entry.numberOfSymbols_                      << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Size Of Optional Header: " << entry.sizeOfOptionalHeader_                 << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Characteristics: "         << chara_str                                   << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Time Date Stamp: "         << entry.timeDateStamp_                        << std::endl;

  return os;

}
}
}
