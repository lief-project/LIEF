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
#include <stdexcept>
#include <iomanip>
#include <functional>
#include <algorithm>
#include <numeric>
#include <iterator>
#include <string>

#include "LIEF/PE/hash.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/exception.hpp"

#include "LIEF/PE/OptionalHeader.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/utils.hpp"


namespace LIEF {
namespace PE {

OptionalHeader::~OptionalHeader(void) = default;
OptionalHeader& OptionalHeader::operator=(const OptionalHeader&) = default;
OptionalHeader::OptionalHeader(const OptionalHeader&) = default;

OptionalHeader::OptionalHeader(void) :
  magic_{},
  majorLinkerVersion_(9), // Arbitrary value
  minorLinkerVersion_(0),
  sizeOfCode_(0),
  sizeOfInitializedData_(0),
  sizeOfUninitializedData_(0),
  addressOfEntryPoint_(0),
  baseOfCode_(0),
  baseOfData_(0),
  imageBase_(0x00400000),
  sectionAlignment_(0x1000),
  fileAlignment_(0x200),
  majorOperatingSystemVersion_(5), // Windows 2000
  minorOperatingSystemVersion_(0),
  majorImageVersion_(0),
  minorImageVersion_(0),
  majorSubsystemVersion_(5),
  minorSubsystemVersion_(0),
  win32VersionValue_(0),
  sizeOfImage_(0),
  sizeOfHeaders_(0),
  checkSum_(0),
  subsystem_(SUBSYSTEM::IMAGE_SUBSYSTEM_WINDOWS_CUI),
  DLLCharacteristics_{},
  sizeOfStackReserve_(0x200000),
  sizeOfStackCommit_(0x1000),
  sizeOfHeapReserve_(0x100000),
  sizeOfHeapCommit_(0x1000),
  loaderFlags_(0),
  numberOfRvaAndSize_(DEFAULT_NUMBER_DATA_DIRECTORIES + 1)
{
  this->sizeOfHeaders_ = sizeof(pe_dos_header) + sizeof(pe_header);
  this->sizeOfHeaders_ = LIEF::align(this->sizeOfHeaders_, this->fileAlignment_);
}


OptionalHeader::OptionalHeader(const pe32_optional_header *header):
  magic_(static_cast<PE_TYPE>(header->Magic)),
  majorLinkerVersion_(header->MajorLinkerVersion),
  minorLinkerVersion_(header->MinorLinkerVersion),
  sizeOfCode_(header->SizeOfCode),
  sizeOfInitializedData_(header->SizeOfInitializedData),
  sizeOfUninitializedData_(header->SizeOfUninitializedData),
  addressOfEntryPoint_(header->AddressOfEntryPoint),
  baseOfCode_(header->BaseOfCode),
  baseOfData_(header->BaseOfData),
  imageBase_(header->ImageBase),
  sectionAlignment_(header->SectionAlignment),
  fileAlignment_(header->FileAlignment),
  majorOperatingSystemVersion_(header->MajorOperatingSystemVersion),
  minorOperatingSystemVersion_(header->MinorOperatingSystemVersion),
  majorImageVersion_(header->MajorImageVersion),
  minorImageVersion_(header->MinorImageVersion),
  majorSubsystemVersion_(header->MajorSubsystemVersion),
  minorSubsystemVersion_(header->MinorSubsystemVersion),
  win32VersionValue_(header->Win32VersionValue),
  sizeOfImage_(header->SizeOfImage),
  sizeOfHeaders_(header->SizeOfHeaders),
  checkSum_(header->CheckSum),
  subsystem_(static_cast<SUBSYSTEM>(header->Subsystem)),
  DLLCharacteristics_(header->DLLCharacteristics),
  sizeOfStackReserve_(header->SizeOfStackReserve),
  sizeOfStackCommit_(header->SizeOfStackCommit),
  sizeOfHeapReserve_(header->SizeOfHeapReserve),
  sizeOfHeapCommit_(header->SizeOfHeapCommit),
  loaderFlags_(header->LoaderFlags),
  numberOfRvaAndSize_(header->NumberOfRvaAndSize)
{}

OptionalHeader::OptionalHeader(const pe64_optional_header *header):
  magic_(static_cast<PE_TYPE>(header->Magic)),
  majorLinkerVersion_(header->MajorLinkerVersion),
  minorLinkerVersion_(header->MinorLinkerVersion),
  sizeOfCode_(header->SizeOfCode),
  sizeOfInitializedData_(header->SizeOfInitializedData),
  sizeOfUninitializedData_(header->SizeOfUninitializedData),
  addressOfEntryPoint_(header->AddressOfEntryPoint),
  baseOfCode_(header->BaseOfCode),
  baseOfData_(0), // Not in PE64
  imageBase_(header->ImageBase),
  sectionAlignment_(header->SectionAlignment),
  fileAlignment_(header->FileAlignment),
  majorOperatingSystemVersion_(header->MajorOperatingSystemVersion),
  minorOperatingSystemVersion_(header->MinorOperatingSystemVersion),
  majorImageVersion_(header->MajorImageVersion),
  minorImageVersion_(header->MinorImageVersion),
  majorSubsystemVersion_(header->MajorSubsystemVersion),
  minorSubsystemVersion_(header->MinorSubsystemVersion),
  win32VersionValue_(header->Win32VersionValue),
  sizeOfImage_(header->SizeOfImage),
  sizeOfHeaders_(header->SizeOfHeaders),
  checkSum_(header->CheckSum),
  subsystem_(static_cast<SUBSYSTEM>(header->Subsystem)),
  DLLCharacteristics_(header->DLLCharacteristics),
  sizeOfStackReserve_(header->SizeOfStackReserve),
  sizeOfStackCommit_(header->SizeOfStackCommit),
  sizeOfHeapReserve_(header->SizeOfHeapReserve),
  sizeOfHeapCommit_(header->SizeOfHeapCommit),
  loaderFlags_(header->LoaderFlags),
  numberOfRvaAndSize_(header->NumberOfRvaAndSize)
{}

PE_TYPE OptionalHeader::magic(void) const {
  return this->magic_;
}


uint8_t OptionalHeader::major_linker_version(void) const {
  return this->majorLinkerVersion_;
}


uint8_t OptionalHeader::minor_linker_version(void) const {
  return this->minorLinkerVersion_;
}


uint32_t OptionalHeader::sizeof_code(void) const {
  return this->sizeOfCode_;
}


uint32_t OptionalHeader::sizeof_initialized_data(void) const {
  return this->sizeOfInitializedData_;
}


uint32_t OptionalHeader::sizeof_uninitialized_data(void) const {
  return this->sizeOfUninitializedData_;
}


uint32_t OptionalHeader::addressof_entrypoint(void) const {
  return this->addressOfEntryPoint_;
}


uint32_t OptionalHeader::baseof_code(void) const {
  return this->baseOfCode_;
}


uint32_t OptionalHeader::baseof_data(void) const {
  if (this->magic() == PE_TYPE::PE32) {
    return this->baseOfData_;
  } else {
    throw LIEF::bad_format("There isn't this attribute in PE32+");
  }
}


uint64_t OptionalHeader::imagebase(void) const {
  return this->imageBase_;
}


uint32_t OptionalHeader::section_alignment(void) const {
  return this->sectionAlignment_;
}


uint32_t OptionalHeader::file_alignment(void) const {
  return this->fileAlignment_;
}


uint16_t OptionalHeader::major_operating_system_version(void) const {
  return this->majorOperatingSystemVersion_;
}


uint16_t OptionalHeader::minor_operating_system_version(void) const {
  return this->minorOperatingSystemVersion_;
}


uint16_t OptionalHeader::major_image_version(void) const {
  return this->majorImageVersion_;
}


uint16_t OptionalHeader::minor_image_version(void) const {
  return this->minorImageVersion_;
}


uint16_t OptionalHeader::major_subsystem_version(void) const {
  return this->majorSubsystemVersion_;
}


uint16_t OptionalHeader::minor_subsystem_version(void) const {
  return this->minorSubsystemVersion_;
}


uint32_t OptionalHeader::win32_version_value(void) const {
  return this->win32VersionValue_;
}


uint32_t OptionalHeader::sizeof_image(void) const {
  return this->sizeOfImage_;
}


uint32_t OptionalHeader::sizeof_headers(void) const {
  return this->sizeOfHeaders_;
}


uint32_t OptionalHeader::checksum(void) const {
  return this->checkSum_;
}


SUBSYSTEM OptionalHeader::subsystem(void) const {
  return this->subsystem_;
}


uint32_t OptionalHeader::dll_characteristics(void) const {
  return this->DLLCharacteristics_;
}


uint64_t OptionalHeader::sizeof_stack_reserve(void) const {
  return this->sizeOfStackReserve_;
}


uint64_t OptionalHeader::sizeof_stack_commit(void) const {
  return this->sizeOfStackCommit_;
}


uint64_t OptionalHeader::sizeof_heap_reserve(void) const {
  return this->sizeOfHeapReserve_;
}


uint64_t OptionalHeader::sizeof_heap_commit(void) const {
  return this->sizeOfHeapCommit_;
}


uint32_t OptionalHeader::loader_flags(void) const {
  return this->loaderFlags_;
}


uint32_t OptionalHeader::numberof_rva_and_size(void) const {
  return this->numberOfRvaAndSize_;
}

bool OptionalHeader::has(DLL_CHARACTERISTICS c) const {
  return (this->dll_characteristics() & static_cast<uint32_t>(c)) > 0;
}

void OptionalHeader::add(DLL_CHARACTERISTICS c) {
  this->dll_characteristics(this->dll_characteristics() | static_cast<uint32_t>(c));
}

void OptionalHeader::remove(DLL_CHARACTERISTICS c) {
  this->dll_characteristics(this->dll_characteristics() & (~ static_cast<uint32_t>(c)));
}


std::set<DLL_CHARACTERISTICS> OptionalHeader::dll_characteristics_list(void) const {
  std::set<DLL_CHARACTERISTICS> dll_charac;
  std::copy_if(
      std::begin(dll_characteristics_array),
      std::end(dll_characteristics_array),
      std::inserter(dll_charac, std::begin(dll_charac)),
      std::bind(&OptionalHeader::has, this, std::placeholders::_1));

  return dll_charac;
}



void OptionalHeader::magic(PE_TYPE magic) {
  this->magic_ = static_cast<PE_TYPE>(magic);
}


void OptionalHeader::major_linker_version(uint8_t majorLinkerVersion) {
  this->majorLinkerVersion_ = majorLinkerVersion;
}


void OptionalHeader::minor_linker_version(uint8_t minorLinkerVersion) {
  this->minorLinkerVersion_ = minorLinkerVersion;
}


void OptionalHeader::sizeof_code(uint32_t sizeOfCode) {
  this->sizeOfCode_ = sizeOfCode;
}


void OptionalHeader::sizeof_initialized_data(uint32_t sizeOfInitializedData) {
  this->sizeOfInitializedData_ = sizeOfInitializedData;
}


void OptionalHeader::sizeof_uninitialized_data(uint32_t sizeOfUninitializedData) {
  this->sizeOfUninitializedData_ = sizeOfUninitializedData;
}


void OptionalHeader::addressof_entrypoint(uint32_t addressOfEntryPoint) {
  this->addressOfEntryPoint_ = addressOfEntryPoint;
}


void OptionalHeader::baseof_code(uint32_t baseOfCode) {
  this->baseOfCode_ = baseOfCode;
}


void OptionalHeader::baseof_data(uint32_t baseOfData) {
  if (this->magic() == PE_TYPE::PE32) {
    this->baseOfData_ = baseOfData;
  } else {
    throw LIEF::bad_format("There isn't this attribute in PE32+");
  }

}


void OptionalHeader::imagebase(uint64_t imageBase) {
  this->imageBase_ = imageBase;
}


void OptionalHeader::section_alignment(uint32_t sectionAlignment) {
  this->sectionAlignment_ = sectionAlignment;
}


void OptionalHeader::file_alignment(uint32_t fileAlignment) {
  this->fileAlignment_ = fileAlignment;
}


void OptionalHeader::major_operating_system_version(uint16_t majorOperatingSystemVersion) {
  this->majorOperatingSystemVersion_ = majorOperatingSystemVersion;
}


void OptionalHeader::minor_operating_system_version(uint16_t minorOperatingSystemVersion) {
  this->minorOperatingSystemVersion_ = minorOperatingSystemVersion;
}


void OptionalHeader::major_image_version(uint16_t majorImageVersion) {
  this->majorImageVersion_ = majorImageVersion;
}


void OptionalHeader::minor_image_version(uint16_t minorImageVersion) {
  this->minorImageVersion_ = minorImageVersion;
}


void OptionalHeader::major_subsystem_version(uint16_t majorSubsystemVersion) {
  this->majorSubsystemVersion_ = majorSubsystemVersion;
}


void OptionalHeader::minor_subsystem_version(uint16_t minorSubsystemVersion) {
  this->minorSubsystemVersion_ = minorSubsystemVersion;
}


void OptionalHeader::win32_version_value(uint32_t win32VersionValue) {
  this->win32VersionValue_ = win32VersionValue;
}


void OptionalHeader::sizeof_image(uint32_t sizeOfImage) {
  this->sizeOfImage_ = sizeOfImage;
}


void OptionalHeader::sizeof_headers(uint32_t sizeOfHeaders) {
  this->sizeOfHeaders_ = sizeOfHeaders;
}


void OptionalHeader::checksum(uint32_t checkSum) {
  this->checkSum_ = checkSum;
}


void OptionalHeader::subsystem(SUBSYSTEM subsystem) {
  this->subsystem_ = subsystem;
}


void OptionalHeader::dll_characteristics(uint32_t DLLCharacteristics) {
  this->DLLCharacteristics_ = DLLCharacteristics;
}


void OptionalHeader::sizeof_stack_reserve(uint64_t sizeOfStackReserve) {
  this->sizeOfStackReserve_ = sizeOfStackReserve;
}


void OptionalHeader::sizeof_stack_commit(uint64_t sizeOfStackCommit) {
  this->sizeOfStackCommit_ = sizeOfStackCommit;
}


void OptionalHeader::sizeof_heap_reserve(uint64_t sizeOfHeapReserve) {
  this->sizeOfHeapReserve_ = sizeOfHeapReserve;
}


void OptionalHeader::sizeof_heap_commit(uint64_t sizeOfHeapCommit) {
  this->sizeOfHeapCommit_ = sizeOfHeapCommit;
}


void OptionalHeader::loader_flags(uint32_t loaderFlags) {
  this->loaderFlags_ = loaderFlags;
}


void OptionalHeader::numberof_rva_and_size(uint32_t numberOfRvaAndSize) {
  this->numberOfRvaAndSize_ = numberOfRvaAndSize;
}

void OptionalHeader::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}


OptionalHeader& OptionalHeader::operator+=(DLL_CHARACTERISTICS c) {
  this->add(c);
  return *this;
}

OptionalHeader& OptionalHeader::operator-=(DLL_CHARACTERISTICS c) {
  this->remove(c);
  return *this;
}

bool OptionalHeader::operator==(const OptionalHeader& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool OptionalHeader::operator!=(const OptionalHeader& rhs) const {
  return not (*this == rhs);
}


std::ostream& operator<<(std::ostream& os, const OptionalHeader& entry) {
  const auto& dll_chara = entry.dll_characteristics_list();

  std::string dll_chara_str = std::accumulate(
     std::begin(dll_chara),
     std::end(dll_chara), std::string{},
     [] (const std::string& a, DLL_CHARACTERISTICS b) {
         return a.empty() ? std::string("\n- ") + to_string(b) : a + "\n- " + to_string(b);
     });

  os << std::hex;
  os << std::setw(33) << std::left << std::setfill(' ') << "Magic: "                          << static_cast<uint32_t>(entry.magic())                << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Major Linker Version: "           << static_cast<uint32_t>(entry.major_linker_version()) << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Minor Linker Version: "           << static_cast<uint32_t>(entry.minor_linker_version()) << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Code: "                   << entry.sizeOfCode_                                   << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Initialized Data: "       << entry.sizeOfInitializedData_                        << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Uninitialized Data: "     << entry.sizeOfUninitializedData_                      << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Address Of Entry Point: "         << entry.addressOfEntryPoint_                          << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Base Of Code: "                   << entry.baseOfCode_                                   << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Base Of Data: "                   << entry.baseOfData_                                   << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Image Base: "                     << entry.imageBase_                                    << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Section Alignment: "              << entry.sectionAlignment_                             << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "File Alignment: "                 << entry.fileAlignment_                                << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Major Operating System Version: " << entry.majorOperatingSystemVersion_                  << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Minor Operating System Version: " << entry.minorOperatingSystemVersion_                  << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Major Image Version: "            << entry.majorImageVersion_                            << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Minor Image Version: "            << entry.minorImageVersion_                            << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Major Subsystem Version: "        << entry.majorSubsystemVersion_                        << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Minor Subsystem Version: "        << entry.minorSubsystemVersion_                        << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Win32 Version Value: "            << entry.win32VersionValue_                            << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Image: "                  << entry.sizeOfImage_                                  << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Headers: "                << entry.sizeOfHeaders_                                << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "CheckSum: "                       << entry.checkSum_                                     << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Subsystem: "                      << to_string(entry.subsystem_)                         << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "DLL Characteristics: "            << dll_chara_str                                       << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Stack Reserve: "          << entry.sizeOfStackReserve_                           << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Stack Commit: "           << entry.sizeOfStackCommit_                            << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Heap Reserve: "           << entry.sizeOfHeapReserve_                            << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Size Of Heap Commit: "            << entry.sizeOfHeapCommit_                             << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Loader Flags: "                   << entry.loaderFlags_                                  << std::endl;
  os << std::setw(33) << std::left << std::setfill(' ') << "Number Of RVA And Size: "         << entry.numberOfRvaAndSize_                           << std::endl;

  return os;
}

}
}
