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
#include <set>
#include <map>
#include <iomanip>
#include <sstream>

#include "LIEF/exception.hpp"
#include "LIEF/visitors/Hash.hpp"

#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/EnumToString.hpp"

namespace LIEF {
namespace ELF {

static const std::map<ARCH, std::pair<ARCHITECTURES, std::set<MODES>>> arch_elf_to_lief {
  {ARCH::EM_NONE,      {ARCH_NONE, {}}},
  {ARCH::EM_X86_64,    {ARCH_X86,   {MODE_64}}},
  {ARCH::EM_ARM,       {ARCH_ARM,   {}}},
  {ARCH::EM_AARCH64,   {ARCH_ARM64, {}}},
  {ARCH::EM_386,       {ARCH_X86,   {MODE_32}}},
  {ARCH::EM_IA_64,     {ARCH_INTEL, {MODE_64}}},
};


static const std::map<E_TYPE, OBJECT_TYPES> obj_elf_to_lief {
  {E_TYPE::ET_EXEC, OBJECT_TYPES::TYPE_EXECUTABLE},
  {E_TYPE::ET_DYN,  OBJECT_TYPES::TYPE_LIBRARY},
  {E_TYPE::ET_REL,  OBJECT_TYPES::TYPE_OBJECT},
};

Header& Header::operator=(const Header& copy) = default;
Header::Header(const Header& copy)            = default;
Header::~Header(void)                         = default;

Header::Header(void) :
  fileType_{E_TYPE::ET_NONE},
  machineType_{ARCH::EM_NONE},
  objectFileVersion_{VERSION::EV_NONE},
  entryPoint_(0),
  programHeaderOffset_(0),
  sectionHeaderOffset_(0),
  processorFlag_(0),
  headerSize_(0),
  programHeaderSize_(0),
  numberof_segments_(0),
  sizeOfSectionHeaderEntries_(0),
  numberof_sections_(0),
  sectionNameStringTableIdx_(0)
{}


Header::Header(const Elf32_Ehdr *header):
  fileType_(static_cast<E_TYPE>(header->e_type)),
  machineType_(static_cast<ARCH>(header->e_machine)),
  objectFileVersion_(static_cast<VERSION>(header->e_version)),
  entryPoint_(header->e_entry),
  programHeaderOffset_(header->e_phoff),
  sectionHeaderOffset_(header->e_shoff),
  processorFlag_(header->e_flags),
  headerSize_(header->e_ehsize),
  programHeaderSize_(header->e_phentsize),
  numberof_segments_(header->e_phnum),
  sizeOfSectionHeaderEntries_(header->e_shentsize),
  numberof_sections_(header->e_shnum),
  sectionNameStringTableIdx_(header->e_shstrndx)
{
 std::copy(
     reinterpret_cast<const uint8_t*>(header->e_ident),
     reinterpret_cast<const uint8_t*>(header->e_ident) + IDENTITY::EI_NIDENT,
     std::begin(this->identity_));
}

Header::Header(const Elf64_Ehdr *header):
  fileType_(static_cast<E_TYPE>(header->e_type)),
  machineType_(static_cast<ARCH>(header->e_machine)),
  objectFileVersion_(static_cast<VERSION>(header->e_version)),
  entryPoint_(header->e_entry),
  programHeaderOffset_(header->e_phoff),
  sectionHeaderOffset_(header->e_shoff),
  processorFlag_(header->e_flags),
  headerSize_(header->e_ehsize),
  programHeaderSize_(header->e_phentsize),
  numberof_segments_(header->e_phnum),
  sizeOfSectionHeaderEntries_(header->e_shentsize),
  numberof_sections_(header->e_shnum),
  sectionNameStringTableIdx_(header->e_shstrndx)
{
  std::copy(
      reinterpret_cast<const uint8_t*>(header->e_ident),
      reinterpret_cast<const uint8_t*>(header->e_ident) + IDENTITY::EI_NIDENT,
      std::begin(this->identity_));
}


Header::Header(const std::vector<uint8_t>& header) {
  //TODO: Add more check
  if (header[1] == 'E' and header[2] == 'L' and header[3] == 'F') {
      uint32_t type = reinterpret_cast<const Elf32_Ehdr*>(header.data())->e_ident[IDENTITY::EI_CLASS];
      if (type == ELFCLASS32) {
        *this = Header{reinterpret_cast<const Elf32_Ehdr*>(header.data())};
      } else if(type == ELFCLASS64) {
        *this = Header{reinterpret_cast<const Elf64_Ehdr*>(header.data())};
      } else {
        throw corrupted("Incorrect header (Wrong ELFCLASS)");
      }
  } else {
    throw corrupted("Incorrect header (Wrong magic)");
  }
}

E_TYPE Header::file_type(void) const {
  return this->fileType_;
}


ARCH Header::machine_type(void) const {
  return this->machineType_;
}

OBJECT_TYPES Header::abstract_object_type(void) const {
  try {
    return obj_elf_to_lief.at(this->file_type());
  } catch (const std::out_of_range&) {
    throw not_implemented(to_string(this->file_type()));
  }
}


std::pair<ARCHITECTURES, std::set<MODES>> Header::abstract_architecture(void) const {

  try {
    return arch_elf_to_lief.at(this->machine_type());
  } catch (const std::out_of_range&) {
    throw not_implemented(to_string(this->machine_type()));
  }
}


VERSION Header::object_file_version(void) const {
  return this->objectFileVersion_;
}


uint64_t Header::entrypoint(void) const {
  return this->entryPoint_;
}


uint64_t Header::program_headers_offset(void) const {
  return this->programHeaderOffset_;
}


uint64_t Header::section_headers_offset(void) const {
  return this->sectionHeaderOffset_;
}


uint32_t Header::processor_flag(void) const {
  return this->processorFlag_;
}


uint32_t Header::header_size(void) const {
  return this->headerSize_;
}


uint32_t Header::program_header_size(void) const {
  return this->programHeaderSize_;
}


uint32_t Header::numberof_segments(void) const {
  return this->numberof_segments_;
}

//! @todo rename
uint32_t Header::sizeof_section_header(void) const {
  return this->sizeOfSectionHeaderEntries_;
}


uint32_t Header::numberof_sections(void) const {
  return this->numberof_sections_;
}


uint32_t Header::section_name_table_idx(void) const {
  return this->sectionNameStringTableIdx_;
}


const Header::identity_t& Header::identity(void) const {
  return this->identity_;
}

Header::identity_t& Header::identity(void) {
  return const_cast<Header::identity_t&>(static_cast<const Header*>(this)->identity());
}

ELF_CLASS Header::identity_class(void) const {
  return static_cast<ELF_CLASS>(this->identity_[IDENTITY::EI_CLASS]);
}

ELF_DATA Header::identity_data(void) const {
  return static_cast<ELF_DATA>(this->identity_[IDENTITY::EI_DATA]);
}

VERSION Header::identity_version(void) const {
  return static_cast<VERSION>(this->identity_[IDENTITY::EI_VERSION]);
}

OS_ABI Header::identity_os_abi(void) const {
  return static_cast<OS_ABI>(this->identity_[IDENTITY::EI_OSABI]);
}

void Header::file_type(E_TYPE type) {
  this->fileType_ = type;
}


void Header::machine_type(ARCH machineType) {
  this->machineType_ = machineType;
}


void Header::object_file_version(VERSION version) {
  this->objectFileVersion_ = version;
}


void Header::entrypoint(uint64_t entryPoint) {
  this->entryPoint_ = entryPoint;
}


void Header::program_headers_offset(uint64_t programHeaderOffset) {
  this->programHeaderOffset_ = programHeaderOffset;
}


void Header::section_headers_offset(uint64_t sectionHeaderOffset) {
  this->sectionHeaderOffset_ = sectionHeaderOffset;
}


void Header::processor_flag(uint32_t processorFlag) {
  this->processorFlag_ = processorFlag;
}


void Header::header_size(uint32_t headerSize) {
  this->headerSize_ = headerSize;
}


void Header::program_header_size(uint32_t programHeaderSize) {
  this->programHeaderSize_ = programHeaderSize;
}


void Header::numberof_segments(uint32_t n) {
  this->numberof_segments_ = n;
}


void Header::sizeof_section_header(uint32_t sizeOfSectionHeaderEntries) {
  this->sizeOfSectionHeaderEntries_ = sizeOfSectionHeaderEntries;
}


void Header::numberof_sections(uint32_t n) {
  this->numberof_sections_ = n;
}


void Header::section_name_table_idx(uint32_t sectionNameStringTableIdx) {
  this->sectionNameStringTableIdx_ = sectionNameStringTableIdx;
}


void Header::identity(const std::string& identity) {
  std::copy(
      std::begin(identity),
      std::end(identity),
      std::begin(this->identity_));
}

void Header::identity(const Header::identity_t& identity) {
  std::copy(
      std::begin(identity),
      std::end(identity),
      std::begin(this->identity_));
}

void Header::identity_class(ELF_CLASS i_class) {
  this->identity_[IDENTITY::EI_CLASS] = static_cast<uint8_t>(i_class);
}

void Header::identity_data(ELF_DATA data) {
  this->identity_[IDENTITY::EI_DATA] = static_cast<uint8_t>(data);
}

void Header::identity_version(VERSION version) {
  this->identity_[IDENTITY::EI_VERSION] = static_cast<uint8_t>(version);
}

void Header::identity_os_abi(OS_ABI osabi) {
  this->identity_[IDENTITY::EI_OSABI] = static_cast<uint8_t>(osabi);
}


void Header::accept(LIEF::Visitor& visitor) const {
  visitor.visit(this->entrypoint());
  visitor.visit(this->file_type());
  visitor.visit(this->machine_type());
  visitor.visit(this->object_file_version());
  visitor.visit(this->entrypoint());
  visitor.visit(this->program_headers_offset());
  visitor.visit(this->section_headers_offset());
  visitor.visit(this->processor_flag());
  visitor.visit(this->header_size());
  visitor.visit(this->program_header_size());
  visitor.visit(this->numberof_segments());
  visitor.visit(this->sizeof_section_header());
  visitor.visit(this->section_name_table_idx());
  visitor.visit(this->identity_class());
  visitor.visit(this->identity_data());
  visitor.visit(this->identity_version());
  visitor.visit(this->identity_os_abi());
}

bool Header::operator==(const Header& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return not (*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const Header& hdr)
{
  const Header::identity_t& identity = const_cast<Header*>(&hdr)->identity();
  std::stringstream ss;
  ss << std::hex;
  ss << static_cast<uint32_t>(identity[IDENTITY::EI_MAG0]) << " ";
  ss << static_cast<uint32_t>(identity[IDENTITY::EI_MAG1]) << " ";
  ss << static_cast<uint32_t>(identity[IDENTITY::EI_MAG2]) << " ";
  ss << static_cast<uint32_t>(identity[IDENTITY::EI_MAG3]) << " ";
  const std::string& ident_magic = ss.str();

  os << std::hex << std::left;
  os << std::setw(33) << std::setfill(' ') << "Magic:"                     << ident_magic << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Class"                      << to_string(hdr.identity_class()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Endianness:"                << to_string(hdr.identity_data()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Version:"                   << to_string(hdr.identity_version()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "OS/ABI:"                    << to_string(hdr.identity_os_abi()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Machine type:"              << to_string(hdr.machine_type()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "File type:"                 << to_string(hdr.file_type()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Object file version:"       << to_string(hdr.object_file_version()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Entry Point:"               << "0x" << hdr.entrypoint() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Program header offset:"     << "0x" << hdr.program_headers_offset() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Section header offset:"     << hdr.section_headers_offset() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Processor Flag"             << hdr.processor_flag() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Header size:"               << hdr.header_size() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Program header size:"       << hdr.program_header_size() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Number of program header:"  << hdr.numberof_segments() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Size of section header:"    << hdr.sizeof_section_header() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Number of section headers:" << hdr.numberof_sections() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Section Name Table idx:"    << hdr.section_name_table_idx() << std::endl;

  return os;
}
}
}
