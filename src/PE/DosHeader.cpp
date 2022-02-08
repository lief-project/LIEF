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

#include "LIEF/PE/hash.hpp"

#include "LIEF/PE/DosHeader.hpp"
#include "PE/Structures.hpp"

namespace LIEF {
namespace PE {

DosHeader::~DosHeader() = default;
DosHeader::DosHeader(const DosHeader&) = default;
DosHeader& DosHeader::operator=(const DosHeader&) = default;

DosHeader::DosHeader() :
  magic_{0x5a4d},
  usedBytesInTheLastPage_{144},
  fileSizeInPages_{3},
  numberOfRelocation_{0},
  headerSizeInParagraphs_{4},
  minimumExtraParagraphs_{0},
  maximumExtraParagraphs_{0xFFFF},
  initialRelativeSS_{0},
  initialSP_{0xb8},
  checksum_{0},
  initialIP_{0},
  initialRelativeCS_{0},
  addressOfRelocationTable_{0x40},
  overlayNumber_{0},
  reserved_{0},
  oEMid_{0},
  oEMinfo_{0},
  reserved2_{0},
  addressOfNewExeHeader_{0xF0} // or 0xE8
{}

DosHeader::DosHeader(const details::pe_dos_header& header) :
  magic_{header.Magic},
  usedBytesInTheLastPage_{header.UsedBytesInTheLastPage},
  fileSizeInPages_{header.FileSizeInPages},
  numberOfRelocation_{header.NumberOfRelocationItems},
  headerSizeInParagraphs_{header.HeaderSizeInParagraphs},
  minimumExtraParagraphs_{header.MinimumExtraParagraphs},
  maximumExtraParagraphs_{header.MaximumExtraParagraphs},
  initialRelativeSS_{header.InitialRelativeSS},
  initialSP_{header.InitialSP},
  checksum_{header.Checksum},
  initialIP_{header.InitialIP},
  initialRelativeCS_{header.InitialRelativeCS},
  addressOfRelocationTable_{header.AddressOfRelocationTable},
  overlayNumber_{header.OverlayNumber},
  oEMid_{header.OEMid},
  oEMinfo_{header.OEMinfo},
  addressOfNewExeHeader_{header.AddressOfNewExeHeader}
{
  std::copy(
      reinterpret_cast<const uint16_t*>(header.Reserved),
      reinterpret_cast<const uint16_t*>(header.Reserved)  + 4,
      std::begin(reserved_));
  std::copy(
      reinterpret_cast<const uint16_t*>(header.Reserved2),
      reinterpret_cast<const uint16_t*>(header.Reserved2) + 10,
      std::begin(reserved2_));
}


uint16_t DosHeader::magic() const {
  return magic_;
}


uint16_t DosHeader::used_bytes_in_the_last_page() const {
  return usedBytesInTheLastPage_;
}


uint16_t DosHeader::file_size_in_pages() const {
  return fileSizeInPages_;
}


uint16_t DosHeader::numberof_relocation() const {
  return numberOfRelocation_;
}


uint16_t DosHeader::header_size_in_paragraphs() const {
  return headerSizeInParagraphs_;
}


uint16_t DosHeader::minimum_extra_paragraphs() const {
  return minimumExtraParagraphs_;
}


uint16_t DosHeader::maximum_extra_paragraphs() const {
  return maximumExtraParagraphs_;
}


uint16_t DosHeader::initial_relative_ss() const {
  return initialRelativeSS_;
}


uint16_t DosHeader::initial_sp() const {
  return initialSP_;
}


uint16_t DosHeader::checksum() const {
  return checksum_;
}


uint16_t DosHeader::initial_ip() const {
  return initialIP_;
}


uint16_t DosHeader::initial_relative_cs() const {
  return initialRelativeCS_;
}


uint16_t DosHeader::addressof_relocation_table() const {
  return addressOfRelocationTable_;
}


uint16_t DosHeader::overlay_number() const {
  return overlayNumber_;
}


std::array<uint16_t, 4> DosHeader::reserved() const {
  return reserved_;
}


uint16_t DosHeader::oem_id() const {
  return oEMid_;
}


uint16_t DosHeader::oem_info() const {
  return oEMinfo_;
}


std::array<uint16_t, 10> DosHeader::reserved2() const {
  return reserved2_;
}


uint32_t DosHeader::addressof_new_exeheader() const {
  return addressOfNewExeHeader_;
}



void DosHeader::magic(uint16_t magic) {
  magic_ = magic;
}


void DosHeader::used_bytes_in_the_last_page(uint16_t usedBytesInTheLastPage) {
  usedBytesInTheLastPage_ = usedBytesInTheLastPage;
}


void DosHeader::file_size_in_pages(uint16_t fileSizeInPages) {
  fileSizeInPages_ = fileSizeInPages;
}


void DosHeader::numberof_relocation(uint16_t numberOfRelocation) {
  numberOfRelocation_ = numberOfRelocation;
}


void DosHeader::header_size_in_paragraphs(uint16_t headerSizeInParagraphs) {
  headerSizeInParagraphs_ = headerSizeInParagraphs;
}


void DosHeader::minimum_extra_paragraphs(uint16_t minimumExtraParagraphs) {
  minimumExtraParagraphs_ = minimumExtraParagraphs;
}


void DosHeader::maximum_extra_paragraphs(uint16_t maximumExtraParagraphs) {
  maximumExtraParagraphs_ = maximumExtraParagraphs;
}


void DosHeader::initial_relative_ss(uint16_t initialRelativeSS) {
  initialRelativeSS_ = initialRelativeSS;
}


void DosHeader::initial_sp(uint16_t initialSP) {
  initialSP_ = initialSP;
}


void DosHeader::checksum(uint16_t checksum) {
  checksum_ = checksum;
}


void DosHeader::initial_ip(uint16_t initialIP) {
  initialIP_ = initialIP;
}


void DosHeader::initial_relative_cs(uint16_t initialRelativeCS) {
  initialRelativeCS_ = initialRelativeCS;
}


void DosHeader::addressof_relocation_table(uint16_t addressOfRelocationTable) {
  addressOfRelocationTable_ = addressOfRelocationTable;
}


void DosHeader::overlay_number(uint16_t overlayNumber) {
  overlayNumber_ = overlayNumber;
}


void DosHeader::reserved(const std::array<uint16_t, 4>& reserved) {
  reserved_ = reserved;
}


void DosHeader::oem_id(uint16_t oEMid) {
  oEMid_ = oEMid;
}


void DosHeader::oem_info(uint16_t oEMinfo) {
  oEMinfo_ = oEMinfo;
}


void DosHeader::reserved2(const std::array<uint16_t, 10>& reserved2) {
  reserved2_ = reserved2;
}


void DosHeader::addressof_new_exeheader(uint32_t addressOfNewExeHeader) {
  addressOfNewExeHeader_ = addressOfNewExeHeader;
}

void DosHeader::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool DosHeader::operator==(const DosHeader& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DosHeader::operator!=(const DosHeader& rhs) const {
  return !(*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const DosHeader& entry) {
  os << std::hex;
  os << std::setw(30) << std::left << std::setfill(' ') << "Magic: "                       << entry.magic_                    << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Used Bytes In The LastPage: "  << entry.usedBytesInTheLastPage_   << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "File Size In Pages: "          << entry.fileSizeInPages_          << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Number Of Relocation: "        << entry.numberOfRelocation_       << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Header Size In Paragraphs: "   << entry.headerSizeInParagraphs_   << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Minimum Extra Paragraphs: "    << entry.minimumExtraParagraphs_   << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Maximum Extra Paragraphs: "    << entry.maximumExtraParagraphs_   << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Initial Relative SS: "         << entry.initialRelativeSS_        << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Initial SP: "                  << entry.initialSP_                << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Checksum: "                    << entry.checksum_                 << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Initial IP: "                  << entry.initialIP_                << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Initial Relative CS: "         << entry.initialRelativeCS_        << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Address Of Relocation Table: " << entry.addressOfRelocationTable_ << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Overlay Number: "              << entry.overlayNumber_            << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "OEM id: "                      << entry.oEMid_                    << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "OEM info: "                    << entry.oEMinfo_                  << std::endl;
  os << std::setw(30) << std::left << std::setfill(' ') << "Address Of New Exe Header: "   << entry.addressOfNewExeHeader_    << std::endl;
  return os;
}

}
}
