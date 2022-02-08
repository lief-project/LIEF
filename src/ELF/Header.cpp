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
#include <set>
#include <map>
#include <iomanip>
#include <sstream>
#include <numeric>

#include "frozen.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/ELF/hash.hpp"

#include "LIEF/ELF/Header.hpp"
#include "LIEF/ELF/EnumToString.hpp"
#include "ELF/Structures.hpp"

#include "logging.hpp"

namespace LIEF {
namespace ELF {

static const std::map<ARCH, Header::abstract_architecture_t> arch_elf_to_lief {
  {ARCH::EM_NONE,      {ARCH_NONE,  {}}},
  {ARCH::EM_X86_64,    {ARCH_X86,   {MODE_64}}},
  {ARCH::EM_ARM,       {ARCH_ARM,   {MODE_32}}},
  {ARCH::EM_AARCH64,   {ARCH_ARM64, {MODE_64}}},
  {ARCH::EM_386,       {ARCH_X86,   {MODE_32}}},
  {ARCH::EM_IA_64,     {ARCH_INTEL, {MODE_64}}},
  {ARCH::EM_MIPS,      {ARCH_MIPS,  {MODE_32}}},
  {ARCH::EM_PPC,       {ARCH_PPC,   {MODE_32}}},
  {ARCH::EM_PPC64,     {ARCH_PPC,   {MODE_64}}},
  {ARCH::EM_RISCV,     {ARCH_RISCV, {MODE_64}}},
};

static const std::map<E_TYPE, OBJECT_TYPES> obj_elf_to_lief {
  {E_TYPE::ET_EXEC, OBJECT_TYPES::TYPE_EXECUTABLE},
  {E_TYPE::ET_DYN,  OBJECT_TYPES::TYPE_LIBRARY},
  {E_TYPE::ET_REL,  OBJECT_TYPES::TYPE_OBJECT},
};

static const std::map<ELF_DATA, ENDIANNESS> endi_elf_to_lief {
  {ELF_DATA::ELFDATANONE, ENDIANNESS::ENDIAN_NONE},
  {ELF_DATA::ELFDATA2LSB, ENDIANNESS::ENDIAN_LITTLE},
  {ELF_DATA::ELFDATA2MSB, ENDIANNESS::ENDIAN_BIG},
};


Header& Header::operator=(const Header&) = default;
Header::Header(const Header&)            = default;
Header::~Header()                    = default;

Header::Header() :
  file_type_{E_TYPE::ET_NONE},
  machine_type_{ARCH::EM_NONE},
  object_file_version_{VERSION::EV_NONE},
  entrypoint_(0),
  program_headers_offset_(0),
  section_headers_offset_(0),
  processor_flags_(0),
  header_size_(0),
  program_header_size_(0),
  numberof_segments_(0),
  section_header_size_(0),
  numberof_sections_(0),
  section_string_table_idx_(0)
{}


Header::Header(const details::Elf32_Ehdr& header):
  file_type_(static_cast<E_TYPE>(header.e_type)),
  machine_type_(static_cast<ARCH>(header.e_machine)),
  object_file_version_(static_cast<VERSION>(header.e_version)),
  entrypoint_(header.e_entry),
  program_headers_offset_(header.e_phoff),
  section_headers_offset_(header.e_shoff),
  processor_flags_(header.e_flags),
  header_size_(header.e_ehsize),
  program_header_size_(header.e_phentsize),
  numberof_segments_(header.e_phnum),
  section_header_size_(header.e_shentsize),
  numberof_sections_(header.e_shnum),
  section_string_table_idx_(header.e_shstrndx)
{
 std::copy(
     reinterpret_cast<const uint8_t*>(header.e_ident),
     reinterpret_cast<const uint8_t*>(header.e_ident) + static_cast<size_t>(IDENTITY::EI_NIDENT),
     std::begin(identity_));
}

Header::Header(const details::Elf64_Ehdr& header):
  file_type_(static_cast<E_TYPE>(header.e_type)),
  machine_type_(static_cast<ARCH>(header.e_machine)),
  object_file_version_(static_cast<VERSION>(header.e_version)),
  entrypoint_(header.e_entry),
  program_headers_offset_(header.e_phoff),
  section_headers_offset_(header.e_shoff),
  processor_flags_(header.e_flags),
  header_size_(header.e_ehsize),
  program_header_size_(header.e_phentsize),
  numberof_segments_(header.e_phnum),
  section_header_size_(header.e_shentsize),
  numberof_sections_(header.e_shnum),
  section_string_table_idx_(header.e_shstrndx)
{
 std::copy(
     reinterpret_cast<const uint8_t*>(header.e_ident),
     reinterpret_cast<const uint8_t*>(header.e_ident) + static_cast<size_t>(IDENTITY::EI_NIDENT),
     std::begin(identity_));
}


E_TYPE Header::file_type() const {
  return file_type_;
}


ARCH Header::machine_type() const {
  return machine_type_;
}

OBJECT_TYPES Header::abstract_object_type() const {
  const auto it = obj_elf_to_lief.find(file_type());
  if (it == std::end(obj_elf_to_lief)) {
    LIEF_ERR("File type {} is not abstracted by LIEF", to_string(file_type()));
    return OBJECT_TYPES::TYPE_NONE;
  }
  return it->second;;
}


Header::abstract_architecture_t Header::abstract_architecture() const {
  const auto it = arch_elf_to_lief.find(machine_type());
  if (it == std::end(arch_elf_to_lief)) {
    LIEF_ERR("{} is not supported!", to_string(machine_type()));
    return {};
  }
  return it->second;
}


ENDIANNESS Header::abstract_endianness() const {
  const auto it = endi_elf_to_lief.find(identity_data());
  if (it == std::end(endi_elf_to_lief)) {
    LIEF_ERR("This endianness can't be abstracted");
    return ENDIANNESS::ENDIAN_NONE;
  }
  return it->second;
}


VERSION Header::object_file_version() const {
  return object_file_version_;
}


uint64_t Header::entrypoint() const {
  return entrypoint_;
}


uint64_t Header::program_headers_offset() const {
  return program_headers_offset_;
}


uint64_t Header::section_headers_offset() const {
  return section_headers_offset_;
}


uint32_t Header::processor_flag() const {
  return processor_flags_;
}


bool Header::has(ARM_EFLAGS f) const {
  if (machine_type() != ARCH::EM_ARM) {
    return false;
  }

  switch (f) {
    case ARM_EFLAGS::EF_ARM_EABI_VER1:
    case ARM_EFLAGS::EF_ARM_EABI_VER2:
    case ARM_EFLAGS::EF_ARM_EABI_VER3:
    case ARM_EFLAGS::EF_ARM_EABI_VER4:
    case ARM_EFLAGS::EF_ARM_EABI_VER5:
      {
        return (processor_flag() & static_cast<uint32_t>(ARM_EFLAGS::EF_ARM_EABIMASK)) == static_cast<uint32_t>(f);
      }
    default:
      {
        return (processor_flag() & static_cast<uint32_t>(f)) > 0;
      }
  }
}

Header::arm_flags_list_t Header::arm_flags_list() const {
  arm_flags_list_t flags;

  std::copy_if(std::begin(details::arm_eflags_array), std::end(details::arm_eflags_array),
               std::inserter(flags, std::begin(flags)),
               [this] (ARM_EFLAGS f) { return has(f); });

  return flags;

}

bool Header::has(MIPS_EFLAGS f) const {

  auto fn = static_cast<uint32_t>(f);
  if (machine_type() != ARCH::EM_MIPS) {
    return false;
  }

  if (machine_type() != ARCH::EM_MIPS_RS3_LE) {
    return false;
  }

  if (machine_type() != ARCH::EM_MIPS_X) {
    return false;
  }

  switch(f) {
    case MIPS_EFLAGS::EF_MIPS_NOREORDER:
    case MIPS_EFLAGS::EF_MIPS_PIC:
    case MIPS_EFLAGS::EF_MIPS_CPIC:
    case MIPS_EFLAGS::EF_MIPS_ABI2:
    case MIPS_EFLAGS::EF_MIPS_32BITMODE:
    case MIPS_EFLAGS::EF_MIPS_FP64:
    case MIPS_EFLAGS::EF_MIPS_NAN2008:
      {
        return (processor_flag() & fn) > 0;
      }

    case MIPS_EFLAGS::EF_MIPS_ABI_O32:
    case MIPS_EFLAGS::EF_MIPS_ABI_O64:
    case MIPS_EFLAGS::EF_MIPS_ABI_EABI32:
    case MIPS_EFLAGS::EF_MIPS_ABI_EABI64:
      {
        return ((processor_flag() & static_cast<uint32_t>(MIPS_EFLAGS::EF_MIPS_ABI)) & fn) > 0;
      }

    case MIPS_EFLAGS::EF_MIPS_MACH_3900:
    case MIPS_EFLAGS::EF_MIPS_MACH_4010:
    case MIPS_EFLAGS::EF_MIPS_MACH_4100:
    case MIPS_EFLAGS::EF_MIPS_MACH_4650:
    case MIPS_EFLAGS::EF_MIPS_MACH_4120:
    case MIPS_EFLAGS::EF_MIPS_MACH_4111:
    case MIPS_EFLAGS::EF_MIPS_MACH_SB1:
    case MIPS_EFLAGS::EF_MIPS_MACH_OCTEON:
    case MIPS_EFLAGS::EF_MIPS_MACH_XLR:
    case MIPS_EFLAGS::EF_MIPS_MACH_OCTEON2:
    case MIPS_EFLAGS::EF_MIPS_MACH_OCTEON3:
    case MIPS_EFLAGS::EF_MIPS_MACH_5400:
    case MIPS_EFLAGS::EF_MIPS_MACH_5900:
    case MIPS_EFLAGS::EF_MIPS_MACH_5500:
    case MIPS_EFLAGS::EF_MIPS_MACH_9000:
    case MIPS_EFLAGS::EF_MIPS_MACH_LS2E:
    case MIPS_EFLAGS::EF_MIPS_MACH_LS2F:
    case MIPS_EFLAGS::EF_MIPS_MACH_LS3A:
      {
        return ((processor_flag() & static_cast<uint32_t>(MIPS_EFLAGS::EF_MIPS_MACH)) & fn) > 0;
      }


    case MIPS_EFLAGS::EF_MIPS_MICROMIPS:
    case MIPS_EFLAGS::EF_MIPS_ARCH_ASE_M16:
    case MIPS_EFLAGS::EF_MIPS_ARCH_ASE_MDMX:
      {
        return ((processor_flag() & static_cast<uint32_t>(MIPS_EFLAGS::EF_MIPS_ARCH_ASE)) & fn) > 0;
      }

    case MIPS_EFLAGS::EF_MIPS_ARCH_1:
    case MIPS_EFLAGS::EF_MIPS_ARCH_2:
    case MIPS_EFLAGS::EF_MIPS_ARCH_3:
    case MIPS_EFLAGS::EF_MIPS_ARCH_4:
    case MIPS_EFLAGS::EF_MIPS_ARCH_5:
    case MIPS_EFLAGS::EF_MIPS_ARCH_32:
    case MIPS_EFLAGS::EF_MIPS_ARCH_64:
    case MIPS_EFLAGS::EF_MIPS_ARCH_32R2:
    case MIPS_EFLAGS::EF_MIPS_ARCH_64R2:
    case MIPS_EFLAGS::EF_MIPS_ARCH_32R6:
    case MIPS_EFLAGS::EF_MIPS_ARCH_64R6:
      {
        return (processor_flag() & static_cast<uint32_t>(MIPS_EFLAGS::EF_MIPS_ARCH)) == fn;
      }

    default:
      {
        return (processor_flag() & fn) > 0;
      }
  }


  return (processor_flag() & fn) > 0;
}

Header::mips_flags_list_t Header::mips_flags_list() const {
  mips_flags_list_t flags;

  std::copy_if(
      std::begin(details::mips_eflags_array),
      std::end(details::mips_eflags_array),
      std::inserter(flags, std::begin(flags)),
      [this] (MIPS_EFLAGS f) { return has(f); });

  return flags;

}


bool Header::has(PPC64_EFLAGS f) const {
  if (machine_type() != ARCH::EM_PPC64) {
    return false;
  }

  return (processor_flag() & static_cast<uint32_t>(f)) > 0;
}

Header::ppc64_flags_list_t Header::ppc64_flags_list() const {
  ppc64_flags_list_t flags;

  std::copy_if(
      std::begin(details::ppc64_eflags_array),
      std::end(details::ppc64_eflags_array),
      std::inserter(flags, std::begin(flags)),
      [this] (PPC64_EFLAGS f) { return has(f); });

  return flags;

}


bool Header::has(HEXAGON_EFLAGS f) const {
  if (machine_type() != ARCH::EM_HEXAGON) {
    return false;
  }

  return (processor_flag() & static_cast<uint32_t>(f)) > 0;
}

Header::hexagon_flags_list_t Header::hexagon_flags_list() const {
  hexagon_flags_list_t flags;

  std::copy_if(
      std::begin(details::hexagon_eflags_array),
      std::end(details::hexagon_eflags_array),
      std::inserter(flags, std::begin(flags)),
      [this] (HEXAGON_EFLAGS f) { return has(f); });

  return flags;

}


uint32_t Header::header_size() const {
  return header_size_;
}


uint32_t Header::program_header_size() const {
  return program_header_size_;
}


uint32_t Header::numberof_segments() const {
  return numberof_segments_;
}

uint32_t Header::section_header_size() const {
  return section_header_size_;
}

uint32_t Header::numberof_sections() const {
  return numberof_sections_;
}


uint32_t Header::section_name_table_idx() const {
  return section_string_table_idx_;
}


const Header::identity_t& Header::identity() const {
  return identity_;
}

Header::identity_t& Header::identity() {
  return const_cast<Header::identity_t&>(static_cast<const Header*>(this)->identity());
}

ELF_CLASS Header::identity_class() const {
  return static_cast<ELF_CLASS>(identity_[static_cast<size_t>(IDENTITY::EI_CLASS)]);
}

ELF_DATA Header::identity_data() const {
  return static_cast<ELF_DATA>(identity_[static_cast<size_t>(IDENTITY::EI_DATA)]);
}

VERSION Header::identity_version() const {
  return static_cast<VERSION>(identity_[static_cast<size_t>(IDENTITY::EI_VERSION)]);
}

OS_ABI Header::identity_os_abi() const {
  return static_cast<OS_ABI>(identity_[static_cast<size_t>(IDENTITY::EI_OSABI)]);
}

uint32_t Header::identity_abi_version() const {
  return static_cast<uint32_t>(identity_[static_cast<size_t>(IDENTITY::EI_ABIVERSION)]);
}

void Header::file_type(E_TYPE type) {
  file_type_ = type;
}


void Header::machine_type(ARCH machineType) {
  machine_type_ = machineType;
}


void Header::object_file_version(VERSION version) {
  object_file_version_ = version;
}


void Header::entrypoint(uint64_t entryPoint) {
  entrypoint_ = entryPoint;
}


void Header::program_headers_offset(uint64_t programHeaderOffset) {
  program_headers_offset_ = programHeaderOffset;
}


void Header::section_headers_offset(uint64_t sectionHeaderOffset) {
  section_headers_offset_ = sectionHeaderOffset;
}


void Header::processor_flag(uint32_t processorFlag) {
  processor_flags_ = processorFlag;
}


void Header::header_size(uint32_t headerSize) {
  header_size_ = headerSize;
}


void Header::program_header_size(uint32_t programHeaderSize) {
  program_header_size_ = programHeaderSize;
}


void Header::numberof_segments(uint32_t n) {
  numberof_segments_ = n;
}


void Header::section_header_size(uint32_t sizeOfSectionHeaderEntries) {
  section_header_size_ = sizeOfSectionHeaderEntries;
}


void Header::numberof_sections(uint32_t n) {
  numberof_sections_ = n;
}


void Header::section_name_table_idx(uint32_t sectionNameStringTableIdx) {
  section_string_table_idx_ = sectionNameStringTableIdx;
}


void Header::identity(const std::string& identity) {
  std::copy(
      std::begin(identity),
      std::end(identity),
      std::begin(identity_));
}

void Header::identity(const Header::identity_t& identity) {
  std::copy(
      std::begin(identity),
      std::end(identity),
      std::begin(identity_));
}

void Header::identity_class(ELF_CLASS i_class) {
  identity_[static_cast<size_t>(IDENTITY::EI_CLASS)] = static_cast<uint8_t>(i_class);
}

void Header::identity_data(ELF_DATA data) {
  identity_[static_cast<size_t>(IDENTITY::EI_DATA)] = static_cast<uint8_t>(data);
}

void Header::identity_version(VERSION version) {
  identity_[static_cast<size_t>(IDENTITY::EI_VERSION)] = static_cast<uint8_t>(version);
}

void Header::identity_os_abi(OS_ABI osabi) {
  identity_[static_cast<size_t>(IDENTITY::EI_OSABI)] = static_cast<uint8_t>(osabi);
}

void Header::identity_abi_version(uint32_t version) {
  identity_[static_cast<size_t>(IDENTITY::EI_ABIVERSION)] = static_cast<uint8_t>(version);
}


void Header::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

bool Header::operator==(const Header& rhs) const {
  if (this == &rhs) {
    return true;
  }

  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Header::operator!=(const Header& rhs) const {
  return !(*this == rhs);
}



std::ostream& operator<<(std::ostream& os, const Header& hdr)
{
  const Header::identity_t& identity = const_cast<Header*>(&hdr)->identity();
  std::stringstream ss;
  ss << std::hex;
  ss << static_cast<uint32_t>(identity[static_cast<size_t>(IDENTITY::EI_MAG0)]) << " ";
  ss << static_cast<uint32_t>(identity[static_cast<size_t>(IDENTITY::EI_MAG1)]) << " ";
  ss << static_cast<uint32_t>(identity[static_cast<size_t>(IDENTITY::EI_MAG2)]) << " ";
  ss << static_cast<uint32_t>(identity[static_cast<size_t>(IDENTITY::EI_MAG3)]) << " ";
  const std::string& ident_magic = ss.str();

  std::string processor_flags_str;

  if (hdr.machine_type() == ARCH::EM_ARM) {
    const Header::arm_flags_list_t& flags = hdr.arm_flags_list();
    processor_flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
     [] (const std::string& a, ARM_EFLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });
  }


  if (hdr.machine_type() == ARCH::EM_PPC64) {
    const Header::ppc64_flags_list_t& flags = hdr.ppc64_flags_list();
    processor_flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
     [] (const std::string& a, PPC64_EFLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });
  }

  if (hdr.machine_type() == ARCH::EM_HEXAGON) {
    const Header::hexagon_flags_list_t& flags = hdr.hexagon_flags_list();
    processor_flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
     [] (const std::string& a, HEXAGON_EFLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });
  }


  if (hdr.machine_type() == ARCH::EM_MIPS ||
      hdr.machine_type() == ARCH::EM_MIPS_RS3_LE ||
      hdr.machine_type() == ARCH::EM_MIPS_X)
  {
    const Header::mips_flags_list_t& flags = hdr.mips_flags_list();
    processor_flags_str = std::accumulate(
     std::begin(flags),
     std::end(flags), std::string{},
     [] (const std::string& a, MIPS_EFLAGS b) {
         return a.empty() ? to_string(b) : a + " " + to_string(b);
     });
  }

  os << std::hex << std::left;
  os << std::setw(33) << std::setfill(' ') << "Magic:"                     << ident_magic << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Class:"                     << to_string(hdr.identity_class()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Endianness:"                << to_string(hdr.identity_data()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Version:"                   << to_string(hdr.identity_version()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "OS/ABI:"                    << to_string(hdr.identity_os_abi()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "ABI Version:"               << std::dec << hdr.identity_abi_version() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Machine type:"              << to_string(hdr.machine_type()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "File type:"                 << to_string(hdr.file_type()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Object file version:"       << to_string(hdr.object_file_version()) << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Entry Point:"               << "0x" << hdr.entrypoint() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Program header offset:"     << "0x" << hdr.program_headers_offset() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Section header offset:"     << hdr.section_headers_offset() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Processor Flag:"            << hdr.processor_flag() << " " << processor_flags_str << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Header size:"               << hdr.header_size() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Size of program header:"    << hdr.program_header_size() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Number of program header:"  << hdr.numberof_segments() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Size of section header:"    << hdr.section_header_size() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Number of section headers:" << hdr.numberof_sections() << std::endl;
  os << std::setw(33) << std::setfill(' ') << "Section Name Table idx:"    << hdr.section_name_table_idx() << std::endl;

  return os;
}
}
}
