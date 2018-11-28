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
#include <utility>
#include <algorithm>
#include <iterator>
#include <map>
#include <numeric>
#include <limits>

#include "LIEF/logging++.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"

namespace LIEF {
namespace PE {

static const std::map<MACHINE_TYPES, std::pair<ARCHITECTURES, std::set<MODES>>> arch_pe_to_lief {
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN,   {ARCH_NONE,  {}}},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64,     {ARCH_X86,   {MODE_64}}},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_ARM,       {ARCH_ARM,   {MODE_32}}}, // MODE_LITTLE_ENDIAN
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_ARMNT,     {ARCH_ARM,   {MODE_32, MODE_V7, MODE_THUMB}}},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_ARM64,     {ARCH_ARM64, {MODE_64, MODE_V8}}},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_I386,      {ARCH_X86,   {MODE_32}}},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_IA64,      {ARCH_INTEL, {MODE_64}}},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_THUMB,     {ARCH_ARM,   {MODE_32, MODE_THUMB}}},
};

static const std::map<MACHINE_TYPES, ENDIANNESS> arch_pe_to_endi_lief {
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_UNKNOWN,   ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_AM33,      ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64,     ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_ARM,       ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_ARMNT,     ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_ARM64,     ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_EBC,       ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_I386,      ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_IA64,      ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_M32R,      ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_MIPS16,    ENDIANNESS::ENDIAN_BIG},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_MIPSFPU,   ENDIANNESS::ENDIAN_BIG},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_MIPSFPU16, ENDIANNESS::ENDIAN_BIG},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_POWERPC,   ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_POWERPCFP, ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_R4000,     ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_RISCV32,   ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_RISCV64,   ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_RISCV128,  ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_SH3,       ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_SH3DSP,    ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_SH4,       ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_SH5,       ENDIANNESS::ENDIAN_NONE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_THUMB,     ENDIANNESS::ENDIAN_LITTLE},
  {MACHINE_TYPES::IMAGE_FILE_MACHINE_WCEMIPSV2, ENDIANNESS::ENDIAN_LITTLE},
};


Binary::Binary(void) :
  dos_header_{},
  rich_header_{},
  header_{},
  optional_header_{},
  available_sections_space_{0},
  has_rich_header_{false},
  has_tls_{false},
  has_imports_{false},
  has_signature_{false},
  has_exports_{false},
  has_resources_{false},
  has_exceptions_{false},
  has_relocations_{false},
  has_debug_{false},
  has_configuration_{false},
  is_reproducible_build_{false},
  tls_{},
  sections_{},
  data_directories_{},
  symbols_{},
  strings_table_{},
  relocations_{},
  resources_{nullptr},
  imports_{},
  export_{},
  debug_{},
  overlay_{},
  dos_stub_{},
  load_configuration_{nullptr}
{}

Binary::~Binary(void) {
  for (Section *section : this->sections_) {
    delete section;
  }

  for (DataDirectory *directory : this->data_directories_) {
    delete directory;
  }

  for (Relocation *relocation : this->relocations_) {
    delete relocation;
  }

  if (this->resources_ != nullptr) {
    delete this->resources_;
  }

  if (this->load_configuration_ != nullptr) {
    delete this->load_configuration_;
  }
}

PE_TYPE Binary::type(void) const {
  return this->type_;
}


Binary::Binary(const std::string& name, PE_TYPE type) :
  Binary::Binary{}
{
  this->type_ = type;
  this->name_ = name;

  if (type == PE_TYPE::PE32) {
    this->header().machine(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386);

    this->header().sizeof_optional_header(sizeof(pe32_optional_header) + (DEFAULT_NUMBER_DATA_DIRECTORIES + 1) * sizeof(pe_data_directory));
    this->header().add_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_32BIT_MACHINE);

    this->optional_header().magic(PE_TYPE::PE32);
  } else {
    this->header().machine(MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64);
    this->header().sizeof_optional_header(sizeof(pe64_optional_header) + (DEFAULT_NUMBER_DATA_DIRECTORIES + 1) * sizeof(pe_data_directory));
    this->header().add_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_LARGE_ADDRESS_AWARE);

    this->optional_header().magic(PE_TYPE::PE32_PLUS);
  }

  // Add data directories
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::EXPORT_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::IMPORT_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::RESOURCE_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::EXCEPTION_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::CERTIFICATE_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::BASE_RELOCATION_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::DEBUG});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::ARCHITECTURE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::GLOBAL_PTR});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::TLS_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::LOAD_CONFIG_TABLE});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::BOUND_IMPORT});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::IAT});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::DELAY_IMPORT_DESCRIPTOR});
  this->data_directories_.emplace_back(new DataDirectory{DATA_DIRECTORY::CLR_RUNTIME_HEADER});

  this->optional_header().sizeof_headers(this->sizeof_headers());
  this->optional_header().sizeof_image(this->virtual_size());
}

void Binary::write(const std::string& filename) {
  Builder builder{this};

  builder.
    build_imports(false).
    patch_imports(false).
    build_relocations(false).
    build_tls(false).
    build_resources(true);

  builder.build();
  builder.write(filename);
}

TLS& Binary::tls(void) {
  return const_cast<TLS&>(static_cast<const Binary*>(this)->tls());
}


const TLS& Binary::tls(void) const {
  return this->tls_;
}

void Binary::tls(const TLS& tls) {
  this->tls_ = tls;
  this->has_tls_ = true;
}    

uint64_t Binary::va_to_offset(uint64_t VA) {

  //TODO: add checks relocation/va < imagebase
  uint64_t rva = VA - this->optional_header().imagebase();
  return this->rva_to_offset(rva);
}

uint64_t Binary::rva_to_offset(uint64_t RVA) {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [RVA] (const Section* section)
      {
        if (section == nullptr) {
          return false;
        }
        return (RVA >= section->virtual_address() and
            RVA < (section->virtual_address() + section->virtual_size()));
      });

  if (it_section == std::end(sections_)) {
    // If not found withint a section,
    // we assume that rva == offset
    return static_cast<uint32_t>(RVA);
  }

  // rva - virtual_address + pointer_to_raw_data
  uint32_t section_alignment = this->optional_header().section_alignment();
  uint32_t file_alignment    = this->optional_header().file_alignment();
  if (section_alignment < 0x1000) {
    section_alignment = file_alignment;
  }

  uint64_t section_va     = (*it_section)->virtual_address();
  uint64_t section_offset = (*it_section)->pointerto_raw_data();

  section_va     = align(section_va, section_alignment);
  section_offset = align(section_offset, file_alignment);
  return ((RVA - section_va) + section_offset);
}

const Section& Binary::section_from_offset(uint64_t offset) const {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&offset] (const Section* section) {
        if (section == nullptr) {
          return false;
        }
        return (
            offset >= section->pointerto_raw_data() and
            offset < (section->pointerto_raw_data() + section->sizeof_raw_data()));
      });

  if (it_section == std::end(this->sections_)) {
    throw LIEF::not_found("Section not found");
  }

  return **it_section;
}

Section& Binary::section_from_offset(uint64_t offset) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_offset(offset));
}


const Section& Binary::section_from_rva(uint64_t virtual_address) const {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&virtual_address] (const Section* section) {
        if (section == nullptr) {
          return false;
        }
        return (
            virtual_address >= section->virtual_address() and
            virtual_address < (section->virtual_address() + section->virtual_size()));
      });

  if (it_section == std::end(this->sections_)) {
    throw LIEF::not_found("Section not found");
  }


  return **it_section;
}

Section& Binary::section_from_rva(uint64_t virtual_address) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_rva(virtual_address));
}



DataDirectory& Binary::data_directory(DATA_DIRECTORY index) {
  return const_cast<DataDirectory&>(static_cast<const Binary*>(this)->data_directory(index));
}

const DataDirectory& Binary::data_directory(DATA_DIRECTORY index) const {
  if (static_cast<size_t>(index) < this->data_directories_.size() and this->data_directories_[static_cast<size_t>(index)] != nullptr) {
    return *this->data_directories_[static_cast<size_t>(index)];
  } else {
    throw not_found("Data directory doesn't exist");
  }
}


bool Binary::has(DATA_DIRECTORY index) const {
  auto&& it = std::find_if(
      std::begin(this->data_directories_),
      std::end(this->data_directories_),
      [index] (const DataDirectory* d) {
        return d->type() == index;
      });
  return it != std::end(this->data_directories_);
}

bool Binary::has_rich_header(void) const {
  return this->has_rich_header_;
}

bool Binary::has_tls(void) const {
  return this->has_tls_;
}

bool Binary::has_imports(void) const {
  return this->has_imports_;
}

bool Binary::has_signature(void) const {
  return this->has_signature_;
}

bool Binary::has_exports(void) const {
  return this->has_exports_;
}

bool Binary::has_resources(void) const {
  return this->has_resources_ and this->resources_ != nullptr;
}

bool Binary::has_exceptions(void) const {
  return this->has(DATA_DIRECTORY::EXPORT_TABLE);
  //return this->has_exceptions_;
}


bool Binary::has_relocations(void) const {
  return this->has_relocations_;
}

bool Binary::has_debug(void) const {
  return this->has_debug_;
}

bool Binary::is_reproducible_build(void) const {
  return this->is_reproducible_build_;
}

bool Binary::has_configuration(void) const {
  return this->has_configuration_ and this->load_configuration_ != nullptr;
}

const LoadConfiguration& Binary::load_configuration(void) const {
  if (not this->has_configuration()) {
    throw not_found("The binary doesn't have load configuration");
  }
  return *this->load_configuration_;
}

LoadConfiguration& Binary::load_configuration(void) {
  return const_cast<LoadConfiguration&>(static_cast<const Binary*>(this)->load_configuration());
}

//
// Interface with LIEF::Binary
//
LIEF::symbols_t Binary::get_abstract_symbols(void) {
  LIEF::symbols_t lief_symbols;
  for (Symbol& s : this->symbols_) {
    lief_symbols.push_back(&s);
  }
  return lief_symbols;
}


// Sections
// ========

it_sections Binary::sections(void) {
  return this->sections_;
}


it_const_sections Binary::sections(void) const {
  return this->sections_;
}

LIEF::sections_t Binary::get_abstract_sections(void) {
  return {std::begin(this->sections_), std::end(this->sections_)};
}


Section& Binary::get_section(const std::string& name) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->get_section(name));
}

const Section& Binary::get_section(const std::string& name) const {
  auto&& section_it = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section)
      {
        return section != nullptr and section->name() == name;
      });

  if (section_it == std::end(this->sections_)) {
    throw LIEF::not_found("No such section with this name");
  }
  return **section_it;
}


const Section& Binary::import_section(void) const {
  if (not this->has_imports()) {
    throw not_found("Current binary doesn't have Import directory");
  }
  const DataDirectory& import_directory = this->data_directory(DATA_DIRECTORY::IMPORT_TABLE);
  return import_directory.section();
}


Section& Binary::import_section(void) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->import_section());
}

// Headers
// =======

// Dos Header
// ----------
DosHeader& Binary::dos_header(void) {
  return const_cast<DosHeader&>(static_cast<const Binary*>(this)->dos_header());
}


const DosHeader& Binary::dos_header(void) const {
  return this->dos_header_;
}


// Standard header
// ---------------
Header& Binary::header(void) {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}


const Header& Binary::header(void) const {
  return this->header_;
}

// Optional Header
// ---------------
const OptionalHeader& Binary::optional_header(void) const {
  return this->optional_header_;
}


OptionalHeader& Binary::optional_header(void) {
  return const_cast<OptionalHeader&>(static_cast<const Binary*>(this)->optional_header());
}




uint64_t Binary::virtual_size(void) const {
  uint64_t size = 0;
  size += this->dos_header().addressof_new_exeheader();
  size += sizeof(pe_header);
  if (this->type_ == PE_TYPE::PE32) {
    size += sizeof(pe32_optional_header);
  } else {
    size += sizeof(pe64_optional_header);
  }
  for (const Section* section : this->sections_) {
    size = std::max(size, section->virtual_address() + section->virtual_size());
  }
  size = LIEF::align(size, this->optional_header().section_alignment());
  return size;
}


uint32_t Binary::sizeof_headers(void) const {
  uint32_t size = 0;
  size += this->dos_header().addressof_new_exeheader();
  size += sizeof(pe_header);
  if (this->type_ == PE_TYPE::PE32) {
    size += sizeof(pe32_optional_header);
  } else {
    size += sizeof(pe64_optional_header);
  }

  size += sizeof(pe_data_directory) * (this->data_directories_.size() + 1);
  size += sizeof(pe_section) * (this->sections_.size() + 1);
  size = static_cast<uint32_t>(LIEF::align(size, this->optional_header().file_alignment()));
  return size;

}

void Binary::remove_section(const std::string& name, bool clear) {


  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&name] (const Section* section) {
        return section->name() == name;
      });

  if (it_section == std::end(this->sections_)) {
    LOG(ERROR) << "Unable to find section: '" << name << "'" << std::endl;
    return;
  }

  return this->remove(**it_section, clear);
}


void Binary::remove(const Section& section, bool clear) {
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&section] (const Section* s) {
        return *s == section;
      });
  if (it_section == std::end(this->sections_)) {
    LOG(ERROR) << "Unable to find section: '" << section.name() << "'" << std::endl;
    return;
  }

  Section* to_remove = *it_section;
  const size_t section_index = std::distance(std::begin(this->sections_), it_section);

  if (section_index < (this->sections_.size() - 1) and section_index > 0) {
    Section* previous = this->sections_[section_index - 1];
    const size_t raw_size_gap = (to_remove->offset() + to_remove->size()) - (previous->offset() + previous->size());
    previous->size(previous->size() + raw_size_gap);

    const size_t vsize_size_gap = (to_remove->virtual_address() + to_remove->virtual_size()) - (previous->virtual_address() + previous->virtual_size());
    previous->virtual_size(previous->virtual_size() + vsize_size_gap);
  }


  if (clear) {
    to_remove->clear(0);
  }

  delete to_remove;
  this->sections_.erase(it_section);

  this->header().numberof_sections(this->header().numberof_sections() - 1);

  this->optional_header().sizeof_headers(this->sizeof_headers());
  this->optional_header().sizeof_image(static_cast<uint32_t>(this->virtual_size()));
}

void Binary::make_space_for_new_section(void) {
  const uint32_t shift = align(sizeof(pe_section), this->optional_header().file_alignment());
  VLOG(VDEBUG) << "Making space for a new section header";
  VLOG(VDEBUG) << "Shifting all sections by " << std::hex << std::showbase << shift;

  // Shift offset of the section content by the size of
  // a section header aligned on "file alignment"
  for (Section* section : this->sections_) {
    section->pointerto_raw_data(section->pointerto_raw_data() + shift);
  }
  this->available_sections_space_++;
}

Section& Binary::add_section(const Section& section, PE_SECTION_TYPES type) {

  if (this->available_sections_space_ < 0) {
    this->make_space_for_new_section();
    return this->add_section(section, type);
  }

  // Check if a section of type **type** already exist
  auto&& it_section = std::find_if(
      std::begin(this->sections_),
      std::end(this->sections_),
      [&type] (const Section* s) {
        return s != nullptr and s->is_type(type);
      });

  if (it_section != std::end(this->sections_)) {
    Section* s = *it_section;
    s->remove_type(type);
  }

  Section* new_section                = new Section{section};
  std::vector<uint8_t> content        = new_section->content();
  const uint32_t section_size         = static_cast<uint32_t>(content.size());
  const uint32_t section_size_aligned = static_cast<uint32_t>(align(section_size, this->optional_header().file_alignment()));
  const uint32_t virtual_size         = section_size;

  content.insert(std::end(content), section_size_aligned - section_size, 0);
  new_section->content(content);

  // Compute new section offset
  uint64_t new_section_offset = align(std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), this->sizeof_headers(),
      [] (uint64_t offset, const Section* s) {
        return std::max<uint64_t>(s->pointerto_raw_data() + s->sizeof_raw_data(), offset);
      }), this->optional_header().file_alignment());

  VLOG(VDEBUG) << "New section offset: 0x" << std::hex << new_section_offset;


  // Compute new section Virtual address
  const uint64_t new_section_va = align(std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), this->optional_header().section_alignment(),
      [] (uint64_t va, const Section* s) {
        return std::max<uint64_t>(s->virtual_address() + s->virtual_size(), va);
      }), this->optional_header().section_alignment());

  VLOG(VDEBUG) << "New section va: 0x" << std::hex << new_section_va;

  new_section->add_type(type);

  if (new_section->pointerto_raw_data() == 0) {
    new_section->pointerto_raw_data(new_section_offset);
  }

  if (new_section->sizeof_raw_data() == 0) {
    new_section->sizeof_raw_data(section_size_aligned);
  }

  if (new_section->virtual_address() == 0) {
    new_section->virtual_address(new_section_va);
  }

  if (new_section->virtual_size() == 0) {
    new_section->virtual_size(virtual_size);
  }

  if (new_section->is_type(PE_SECTION_TYPES::TEXT)) {
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
    this->optional_header().baseof_code(static_cast<uint32_t>(new_section->virtual_address()));
    this->optional_header().sizeof_code(new_section->sizeof_raw_data());
  }

  if (new_section->is_type(PE_SECTION_TYPES::DATA)) {
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

    if (this->type() == PE_TYPE::PE32) {
      this->optional_header().baseof_data(static_cast<uint32_t>(new_section->virtual_address()));
    }
    this->optional_header().sizeof_initialized_data(new_section->sizeof_raw_data());
  }


  if (type == PE_SECTION_TYPES::IMPORT) {

    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

    this->data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA(new_section->virtual_address());
    this->data_directory(DATA_DIRECTORY::IMPORT_TABLE).size(new_section->sizeof_raw_data());
    this->data_directory(DATA_DIRECTORY::IMPORT_TABLE).section_ = new_section;
    this->data_directory(DATA_DIRECTORY::IAT).RVA(0);
    this->data_directory(DATA_DIRECTORY::IAT).size(0);
  }

  if (type == PE_SECTION_TYPES::RELOCATION) {
    this->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA(new_section->virtual_address());
    this->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size(new_section->virtual_size());
    this->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).section_ = new_section;
  }

  if (type == PE_SECTION_TYPES::RESOURCE) {
    this->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA(new_section->virtual_address());
    this->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).size(new_section->size());
    this->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).section_ = new_section;
  }

  if (type == PE_SECTION_TYPES::TLS) {
    this->data_directory(DATA_DIRECTORY::TLS_TABLE).RVA(new_section->virtual_address());
    this->data_directory(DATA_DIRECTORY::TLS_TABLE).size(new_section->size());
    this->data_directory(DATA_DIRECTORY::TLS_TABLE).section_ = new_section;
  }


  if (this->sections_.size() >= std::numeric_limits<uint16_t>::max()) {
    throw pe_error("Binary reachs its maximum number of sections");
  }

  this->available_sections_space_--;
  this->sections_.push_back(new_section);

  // Update headers
  this->header().numberof_sections(static_cast<uint16_t>(this->sections_.size()));

  this->optional_header().sizeof_image(this->virtual_size());
  this->optional_header().sizeof_headers(this->sizeof_headers());
  return *(this->sections_.back());
}


//////////////////////////////////
//
// Methods to manage relocations
//
//////////////////////////////////

it_relocations Binary::relocations(void) {
  return this->relocations_;
}


it_const_relocations Binary::relocations(void) const {
  return this->relocations_;
}


Relocation& Binary::add_relocation(const Relocation& relocation) {
  Relocation* newone = new Relocation{relocation};
  this->relocations_.push_back(newone);
  return *newone;
}


//void Binary::remove_relocation(std::vector<Relocation>::iterator it) {
//  this->relocations_.erase(it);
//}


void Binary::remove_all_relocations(void) {
  for (Relocation* r : this->relocations_) {
    delete r;
  }
  this->relocations_.clear();
}


LIEF::relocations_t Binary::get_abstract_relocations(void) {
  LIEF::relocations_t abstract_relocs;
  for (Relocation& relocation : this->relocations()) {
    for (RelocationEntry& entry : relocation.entries()) {
      abstract_relocs.push_back(&entry);
    }
  }
  return abstract_relocs;
}

// Imports
// =======

it_imports Binary::imports(void) {
  return {this->imports_};
}

it_const_imports Binary::imports(void) const {
  return {this->imports_};
}

ImportEntry& Binary::add_import_function(const std::string& library, const std::string& function) {
  auto&& it_import = std::find_if(
      std::begin(this->imports_),
      std::end(this->imports_),
      [&library] (const Import& import)
      {
        return import.name() == library;
      });

  if (it_import == std::end(this->imports_)) {
    //TODO: add the library
    throw not_found("The library doesn't exist");
  }

  it_import->add_entry({function});
  return it_import->get_entry(function);
}

Import& Binary::add_library(const std::string& name) {
  this->imports_.emplace_back(name);
  if (this->imports_.size() > 0) {
    this->has_imports_ = true;
  }
  return this->imports_.back();
}

void Binary::remove_library(const std::string&) {
  throw LIEF::not_implemented("To implement");
}

void Binary::remove_all_libraries(void) {
  this->imports_ = {};
}

uint32_t Binary::predict_function_rva(const std::string& library, const std::string& function) {

  auto&& it_import = std::find_if(
      this->imports_.cbegin(),
      this->imports_.cend(),
      [&library] (const Import& imp) {
        return imp.name() == library;
      });

  if (it_import == std::end(this->imports_)) {
    LOG(ERROR) << "Unable to find library '" << library << "'";
    return 0;
  }

  it_const_import_entries entries = it_import->entries();

  // Some weird library define a function twice
  size_t nb_functions = std::count_if(
      entries.cbegin(),
      entries.cend(),
      [&function](const ImportEntry& entry )
      {
        return not entry.is_ordinal() and entry.name() == function;
      });

  if (nb_functions == 0) {
    LOG(ERROR) << "Unable to find the function '" << function << "' in '" << library + "'.";
    return 0;
  }

  if (nb_functions > 1) {
    LOG(ERROR) << "'" << function << "' is defined " << std::to_string(nb_functions) << " in '" << library << "'.";
    return 0;
  }

  uint32_t import_table_size = static_cast<uint32_t>((this->imports().size() + 1) * sizeof(pe_import)); // +1 for the null entry

  uint32_t address = import_table_size;

  uint32_t lookup_table_size = 0;
  for (const Import& f : this->imports_) {
    if (this->type_ == PE_TYPE::PE32) {
      lookup_table_size += (f.entries().size() + 1) * sizeof(uint32_t);
    } else {
      lookup_table_size += (f.entries().size() + 1) * sizeof(uint64_t);
    }
  }

  address += lookup_table_size;

  for (auto&& it_imp = this->imports_.cbegin();
      (it_imp->name() != library and it_imp != this->imports_.cend());
       ++it_imp) {
    if (this->type_ == PE_TYPE::PE32) {
      address += sizeof(uint32_t) * (it_imp->entries().size() + 1);
    } else {
      address += sizeof(uint64_t) * (it_imp->entries().size() + 1);
    }
  }


  for (auto&& it_func = entries.cbegin();
      (it_func->name() != function and it_func != entries.cend());
       ++it_func) {
    if (this->type_ == PE_TYPE::PE32) {
      address += sizeof(uint32_t);
    } else {
      address += sizeof(uint64_t);
    }
  }


  // We assume the the idata section will be the last section
  const uint64_t next_virtual_address = align(std::accumulate(
      std::begin(this->sections_),
      std::end(this->sections_), this->optional_header().section_alignment(),
      [] (uint64_t va, const Section* s) {
        return std::max<uint64_t>(s->virtual_address() + s->virtual_size(), va);
      }), this->optional_header().section_alignment());

  return next_virtual_address + address;
}


bool Binary::has_import(const std::string& import_name) const {

  auto&& it_import = std::find_if(
      std::begin(this->imports_),
      std::end(this->imports_),
      [&import_name] (const Import& import) {
        return import.name() == import_name;
      });

  return it_import != std::end(this->imports_);
}


Import& Binary::get_import(const std::string& import_name) {
  return const_cast<Import&>(static_cast<const Binary*>(this)->get_import(import_name));
}

const Import& Binary::get_import(const std::string& import_name) const {

  if (not this->has_import(import_name)) {
    throw not_found("Unable to find the '" + import_name + "' library");
  }

  auto&& it_import = std::find_if(
      std::begin(this->imports_),
      std::end(this->imports_),
      [&import_name] (const Import& import) {
        return import.name() == import_name;
      });

  return *it_import;
}


Export& Binary::get_export(void) {
  return const_cast<Export&>(static_cast<const Binary*>(this)->get_export());
}


const Export& Binary::get_export(void) const {
  return this->export_;
}

/////////////////////////////////////
//
// Methods to manage Resources
//
/////////////////////////////////////

void Binary::set_resources(const ResourceDirectory& resource) {
  delete this->resources_;
  this->resources_ = new ResourceDirectory{resource};
}


void Binary::set_resources(const ResourceData& resource) {
  delete this->resources_;
  this->resources_ = new ResourceData{resource};
}

ResourceNode& Binary::resources(void) {
  return const_cast<ResourceNode&>(static_cast<const Binary*>(this)->resources());
}

const ResourceNode& Binary::resources(void) const {
  if (this->resources_ != nullptr) {
    return *this->resources_;
  } else {
    throw not_found("No resources");
  }
}


/////////////////////////////////////
//
// Methods to manage DataDirectories
//
/////////////////////////////////////
it_data_directories Binary::data_directories(void) {
  return it_data_directories{this->data_directories_};
}

it_const_data_directories Binary::data_directories(void) const {
  return it_const_data_directories{this->data_directories_};
}


debug_entries_t& Binary::debug(void) {
  return const_cast<debug_entries_t&>(static_cast<const Binary*>(this)->debug());
}


const debug_entries_t& Binary::debug(void) const {
  return this->debug_;
}

/////////////////////
//
// Various methods
//
/////////////////////

const Signature& Binary::signature(void) const {
  return this->signature_;
}


std::vector<Symbol>& Binary::symbols(void) {
  return const_cast<std::vector<Symbol>&>(static_cast<const Binary*>(this)->symbols());
}


const std::vector<Symbol>& Binary::symbols(void) const {
  return this->symbols_;
}


LIEF::Binary::functions_t Binary::get_abstract_exported_functions(void) const {
  LIEF::Binary::functions_t result;
  if (this->has_exports()) {
    for (const ExportEntry& entry : this->get_export().entries()) {
      const std::string& name = entry.name();
      if(not name.empty()) {
        result.emplace_back(name, entry.address(), Function::flags_list_t{Function::FLAGS::EXPORTED});
      }
    }
  }
  return result;
}

LIEF::Binary::functions_t Binary::get_abstract_imported_functions(void) const {
  LIEF::Binary::functions_t result;
  if (this->has_imports()) {
    for (const Import& import : this->imports()) {
      const Import& resolved = resolve_ordinals(import);
      for (const ImportEntry& entry : resolved.entries()) {
        const std::string& name = entry.name();
        if(not name.empty()) {
          result.emplace_back(name, entry.iat_address(), Function::flags_list_t{Function::FLAGS::IMPORTED});
        }
      }
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_libraries(void) const {
  std::vector<std::string> result;
  for (const Import& import : this->imports()) {
    result.push_back(import.name());
  }
  return result;
}

LIEF::Header Binary::get_abstract_header(void) const {
  LIEF::Header header;

  try {
    const std::pair<ARCHITECTURES, std::set<MODES>>& am = arch_pe_to_lief.at(this->header().machine());
    header.architecture(am.first);
    header.modes(am.second);
  } catch (const std::out_of_range&) {
    throw not_implemented(to_string(this->header().machine()));
  }

  header.entrypoint(this->entrypoint());

  if (this->header().has_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_DLL)) {
    header.object_type(OBJECT_TYPES::TYPE_LIBRARY);
  } else if (this->header().has_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_EXECUTABLE_IMAGE)) {
    header.object_type(OBJECT_TYPES::TYPE_EXECUTABLE);
  } else {
    header.object_type(OBJECT_TYPES::TYPE_NONE);
  }

  try {
    ENDIANNESS endianness = arch_pe_to_endi_lief.at(this->header().machine());
    header.endianness(endianness);
  } catch (const std::out_of_range&) {
    throw not_implemented("Endianness not found for " + std::string(to_string(this->header().machine())));
  }

  return header;
}



void Binary::hook_function(const std::string& function, uint64_t address) {

  for (const Import& import : this->imports_) {
    for (const ImportEntry& import_entry : import.entries()) {
      if (import_entry.name() == function) {
        return hook_function(import.name(), function, address);
      }
    }
  }

  LOG(WARNING) << "Unable to find library associated with function '" << function << "'";
}


void Binary::hook_function(const std::string& library, const std::string& function, uint64_t address) {
  this->hooks_[library][function] = address;
}

// LIEF Interface
// ==============
uint64_t Binary::entrypoint(void) const {
  return this->optional_header().imagebase() + this->optional_header().addressof_entrypoint();
}

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES addr_type) {
  uint64_t rva = address;

  if (addr_type == LIEF::Binary::VA_TYPES::VA or addr_type == LIEF::Binary::VA_TYPES::AUTO) {
    const int64_t delta = address - this->optional_header().imagebase();

    if (delta > 0 or addr_type == LIEF::Binary::VA_TYPES::VA) {
      rva -= this->optional_header().imagebase();
    }
  }

  // Find the section associated with the virtual address
  Section& section_topatch = this->section_from_rva(rva);
  const uint64_t offset = rva - section_topatch.virtual_address();
  std::vector<uint8_t>& content = section_topatch.content_ref();
  std::copy(
      std::begin(patch_value),
      std::end(patch_value),
      content.data() + offset);

}

void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size, LIEF::Binary::VA_TYPES addr_type) {
  if (size > sizeof(patch_value)) {
    LOG(ERROR) << "Invalid size (" << std::to_string(size) << ")";
    return;
  }

  uint64_t rva = address;

  if (addr_type == LIEF::Binary::VA_TYPES::VA or addr_type == LIEF::Binary::VA_TYPES::AUTO) {
    const int64_t delta = address - this->optional_header().imagebase();

    if (delta > 0 or addr_type == LIEF::Binary::VA_TYPES::VA) {
      rva -= this->optional_header().imagebase();
    }
  }

  Section& section_topatch = this->section_from_rva(rva);
  const uint64_t offset = rva - section_topatch.virtual_address();
  std::vector<uint8_t>& content = section_topatch.content_ref();

  std::copy(
      reinterpret_cast<uint8_t*>(&patch_value),
      reinterpret_cast<uint8_t*>(&patch_value) + size,
      content.data() + offset);

}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size, LIEF::Binary::VA_TYPES addr_type) const {
  uint64_t rva = virtual_address;

  if (addr_type == LIEF::Binary::VA_TYPES::VA or addr_type == LIEF::Binary::VA_TYPES::AUTO) {
    const int64_t delta = virtual_address - this->optional_header().imagebase();

    if (delta > 0 or addr_type == LIEF::Binary::VA_TYPES::VA) {
      rva -= this->optional_header().imagebase();
    }
  }
  const Section& section = this->section_from_rva(rva);
  std::vector<uint8_t> content = section.content();
  const uint64_t offset = rva - section.virtual_address();
  uint64_t checked_size = size;
  if ((offset + checked_size) > content.size()) {
    checked_size = checked_size - (offset + checked_size - content.size());
  }

  return {content.data() + offset, content.data() + offset + checked_size};

}

bool Binary::is_pie(void) const {
  return this->optional_header().has(DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
}

bool Binary::has_nx(void) const {
  return this->optional_header().has(DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);
}

// Overlay
// =======

const std::vector<uint8_t>& Binary::overlay(void) const {
  return this->overlay_;
}

std::vector<uint8_t>& Binary::overlay(void) {
  return const_cast<std::vector<uint8_t>&>(static_cast<const Binary*>(this)->overlay());
}

// Dos stub
// ========

const std::vector<uint8_t>& Binary::dos_stub(void) const {
  return this->dos_stub_;
}

std::vector<uint8_t>& Binary::dos_stub(void) {
  return const_cast<std::vector<uint8_t>&>(static_cast<const Binary*>(this)->dos_stub());
}


void Binary::dos_stub(const std::vector<uint8_t>& content) {
  this->dos_stub_ = content;
}

// Rich Header
// -----------
RichHeader& Binary::rich_header(void) {
  return const_cast<RichHeader&>(static_cast<const Binary*>(this)->rich_header());
}

const RichHeader& Binary::rich_header(void) const {
  return this->rich_header_;
}

void Binary::rich_header(const RichHeader& rich_header) {
  this->rich_header_ = rich_header;
  this->has_rich_header_ = true;
}

// Resource manager
// ===============

ResourcesManager Binary::resources_manager(void) {
  if (this->resources_ == nullptr or not this->has_resources()) {
    throw not_found("There is no resources in the binary");
  }
  return ResourcesManager{this->resources_};
}

const ResourcesManager Binary::resources_manager(void) const {
  if (this->resources_ == nullptr or not this->has_resources()) {
    throw not_found("There is no resources in the binary");
  }
  return ResourcesManager{this->resources_};
}


LIEF::Binary::functions_t Binary::ctor_functions(void) const {
  LIEF::Binary::functions_t functions;

  if (this->has_tls()) {
    const std::vector<uint64_t>& clbs = this->tls().callbacks();
    for (size_t i = 0; i < clbs.size(); ++i) {
      functions.emplace_back(
          "tls_" + std::to_string(i),
          clbs[i],
          Function::flags_list_t{Function::FLAGS::CONSTRUCTOR});

    }
  }
  return functions;
}


LIEF::Binary::functions_t Binary::functions(void) const {

  static const auto func_cmd = [] (const Function& lhs, const Function& rhs) {
    return lhs.address() < rhs.address();
  };
  std::set<Function, decltype(func_cmd)> functions_set(func_cmd);

  LIEF::Binary::functions_t exception_functions = this->exception_functions();
  LIEF::Binary::functions_t exported            = this->get_abstract_exported_functions();
  LIEF::Binary::functions_t ctors               = this->ctor_functions();

  std::move(
      std::begin(exception_functions),
      std::end(exception_functions),
      std::inserter(functions_set, std::end(functions_set)));

  std::move(
      std::begin(exported),
      std::end(exported),
      std::inserter(functions_set, std::end(functions_set)));

  std::move(
      std::begin(ctors),
      std::end(ctors),
      std::inserter(functions_set, std::end(functions_set)));

  return {std::begin(functions_set), std::end(functions_set)};
}

LIEF::Binary::functions_t Binary::exception_functions(void) const {
  LIEF::Binary::functions_t functions;
  if (not this->has_exceptions()) {
    return functions;
  }


  const DataDirectory& exception_dir = this->data_directory(DATA_DIRECTORY::EXCEPTION_TABLE);
  std::vector<uint8_t> exception_data = this->get_content_from_virtual_address(exception_dir.RVA(), exception_dir.size());
  VectorStream vs{std::move(exception_data)};
  const size_t nb_entries = vs.size() / sizeof(pe_exception_entry_x64); // TODO: Handle other architectures

  for (size_t i = 0; i < nb_entries; ++i) {
    if (not vs.can_read<pe_exception_entry_x64>()) {
      LOG(ERROR) << "Corrupted entry at " << std::dec << i;
      break;
    }
    const pe_exception_entry_x64& entry = vs.read<pe_exception_entry_x64>();
    Function f{entry.address_start_rva};
    if (entry.address_end_rva > entry.address_start_rva) {
      f.size(entry.address_end_rva - entry.address_start_rva);
    }
    functions.push_back(std::move(f));
  }
  return functions;
}


void Binary::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Binary::operator==(const Binary& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Binary::operator!=(const Binary& rhs) const {
  return not (*this == rhs);
}


std::ostream& Binary::print(std::ostream& os) const {

  os << "Dos Header" << std::endl;
  os << "==========" << std::endl;

  os << this->dos_header();
  os << std::endl;


  if (this->has_rich_header()) {
    os << "Rich Header" << std::endl;
    os << "===========" << std::endl;
    os << this->rich_header() << std::endl;
    os << std::endl;
  }


  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << this->header();
  os << std::endl;


  os << "Optional Header" << std::endl;
  os << "===============" << std::endl;

  os << this->optional_header();
  os << std::endl;


  os << "Data directories" << std::endl;
  os << "================" << std::endl;

  for (const DataDirectory& data_directory : this->data_directories()) {
    os << data_directory << std::endl;
  }
  os << std::endl;


  os << "Sections" << std::endl;
  os << "========" << std::endl;

  for (const Section& section : this->sections()) {
    os << section << std::endl;;
  }
  os << std::endl;


  if (this->has_tls()) {
    os << "TLS" << std::endl;
    os << "===" << std::endl;
    os << this->tls() << std::endl;
    os << std::endl;
  }


  if (this->has_signature()) {
    os << "Signature" << std::endl;
    os << "=========" << std::endl;
    os << this->signature() << std::endl;
    os << std::endl;
  }


  if (this->has_imports()) {
    os << "Imports" << std::endl;
    os << "=======" << std::endl;
    for (const Import& import : this->imports()) {
      os << import << std::endl;
    }
    os << std::endl;
  }


  if (this->has_debug()) {
    os << "Debug" << std::endl;
    os << "=====" << std::endl;
    for (const Debug& debug : this->debug()) {
      os << debug << std::endl;
    }
    os << std::endl;
  }


  if (this->has_relocations()) {
    os << "Relocations" << std::endl;
    os << "===========" << std::endl;
    for (const Relocation& relocation : this->relocations()) {
      os << relocation << std::endl;
    }
    os << std::endl;
  }


  if (this->has_exports()) {
    os << "Export" << std::endl;
    os << "======" << std::endl;
    os << this->get_export() << std::endl;
    os << std::endl;
  }


  if (this->has_resources()) {
    os << "Resources" << std::endl;
    os << "=========" << std::endl;
    os << this->resources_manager() << std::endl;
    os << std::endl;
  }

  os << "Symbols" << std::endl;
  os << "=======" << std::endl;

  for (const Symbol& symbol : this->symbols()) {
    os << symbol << std::endl;;
  }
  os << std::endl;


  if (this->has_configuration()) {
    os << "Load Configuration" << std::endl;
    os << "==================" << std::endl;

    os << this->load_configuration();

    os << std::endl;
  }



  return os;
}

} // namesapce PE
} // namespace LIEF
