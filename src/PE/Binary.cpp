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
#include <utility>
#include <algorithm>
#include <iterator>
#include <map>
#include <numeric>
#include <limits>

#include "logging.hpp"
#include "hash_stream.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Builder.hpp"
#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/PE/ExportEntry.hpp"
#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"
#include "PE/Structures.hpp"

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


Binary::~Binary() = default;

Binary::Binary() {
  format_ = LIEF::EXE_FORMATS::FORMAT_PE;
}


PE_TYPE Binary::type() const {
  return type_;
}


Binary::Binary(const std::string& name, PE_TYPE type) :
  type_{type}
{
  format_ = LIEF::EXE_FORMATS::FORMAT_PE;
  name_ = name;
  Header& hdr = header();
  size_t sizeof_headers = dos_header().addressof_new_exeheader() +
                          sizeof(details::pe_header) +
                          sizeof(details::pe_data_directory) * details::DEFAULT_NUMBER_DATA_DIRECTORIES;
  if (type == PE_TYPE::PE32) {
    hdr.machine(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386);

    hdr.sizeof_optional_header(sizeof(details::pe32_optional_header) +
                               details::DEFAULT_NUMBER_DATA_DIRECTORIES * sizeof(details::pe_data_directory));
    hdr.add_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_32BIT_MACHINE);

    optional_header().magic(PE_TYPE::PE32);
    sizeof_headers += sizeof(details::pe32_optional_header);
    available_sections_space_ = (0x200 - /* sizeof headers */ sizeof_headers) / sizeof(details::pe_section);
  } else {
    hdr.machine(MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64);
    hdr.sizeof_optional_header(sizeof(details::pe64_optional_header) +
                               details::DEFAULT_NUMBER_DATA_DIRECTORIES * sizeof(details::pe_data_directory));
    hdr.add_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_LARGE_ADDRESS_AWARE);

    sizeof_headers += sizeof(details::pe64_optional_header);
    available_sections_space_ = (0x200 - /* sizeof headers */ sizeof_headers) / sizeof(details::pe_section);
    optional_header().magic(PE_TYPE::PE32_PLUS);
  }

  // Add data directories
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::EXPORT_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::IMPORT_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::RESOURCE_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::EXCEPTION_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::CERTIFICATE_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::BASE_RELOCATION_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::DEBUG));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::ARCHITECTURE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::GLOBAL_PTR));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::TLS_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::LOAD_CONFIG_TABLE));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::BOUND_IMPORT));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::IAT));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::DELAY_IMPORT_DESCRIPTOR));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::CLR_RUNTIME_HEADER));
  data_directories_.push_back(std::make_unique<DataDirectory>(DATA_DIRECTORY::RESERVED));

  optional_header().sizeof_headers(this->sizeof_headers());
  optional_header().sizeof_image(virtual_size());
}

template<typename T>
static void write_impl(Binary& binary, T&& dest)
{
  Builder builder{binary};

  builder.
    build_imports(false).
    patch_imports(false).
    build_relocations(false).
    build_tls(false).
    build_resources(true);

  builder.build();
  builder.write(dest);
}

void Binary::write(const std::string& filename) {
  write_impl(*this, filename);
}

void Binary::write(std::ostream& os) {
  write_impl(*this, os);
}

TLS& Binary::tls() {
  return const_cast<TLS&>(static_cast<const Binary*>(this)->tls());
}


const TLS& Binary::tls() const {
  return tls_;
}

void Binary::tls(const TLS& tls) {
  tls_ = tls;
  has_tls_ = true;
}

uint64_t Binary::va_to_offset(uint64_t VA) {

  //TODO: add checks relocation/va < imagebase
  uint64_t rva = VA - optional_header().imagebase();
  return rva_to_offset(rva);
}

uint64_t Binary::imagebase() const {
  return optional_header().imagebase();
}

result<uint64_t> Binary::offset_to_virtual_address(uint64_t offset, uint64_t slide) const {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [offset] (const std::unique_ptr<Section>& section) {
        return (offset >= section->offset() &&
                offset < (section->offset() + section->sizeof_raw_data()));
      });

  if (it_section == std::end(sections_)) {
    if (slide > 0) {
      return slide + offset;
    }
    return offset;
  }
  const std::unique_ptr<Section>& section = *it_section;
  const uint64_t base_rva = section->virtual_address() - section->offset();
  if (slide > 0) {
    return slide + base_rva + offset;
  }

  return base_rva + offset;
}

uint64_t Binary::rva_to_offset(uint64_t RVA) {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [RVA] (const std::unique_ptr<Section>& section) {
        const auto vsize_adj = std::max<uint64_t>(section->virtual_size(), section->sizeof_raw_data());
        return section->virtual_address() <= RVA &&
               RVA < (section->virtual_address() + vsize_adj);
      });

  if (it_section == std::end(sections_)) {
    // If not found within a section,
    // we assume that rva == offset
    return RVA;
  }
  const std::unique_ptr<Section>& section = *it_section;

  // rva - virtual_address + pointer_to_raw_data
  uint32_t section_alignment = optional_header().section_alignment();
  uint32_t file_alignment    = optional_header().file_alignment();
  if (section_alignment < 0x1000) {
    section_alignment = file_alignment;
  }

  uint64_t section_va     = section->virtual_address();
  uint64_t section_offset = section->pointerto_raw_data();

  section_va     = align(section_va, section_alignment);
  section_offset = align(section_offset, file_alignment);
  return ((RVA - section_va) + section_offset);
}

const Section* Binary::section_from_offset(uint64_t offset) const {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [&offset] (const std::unique_ptr<Section>& section) {
        return section->pointerto_raw_data() <= offset &&
               offset < (section->pointerto_raw_data() + section->sizeof_raw_data());
      });

  if (it_section == std::end(sections_)) {
    return nullptr;
  }

  return it_section->get();
}

Section* Binary::section_from_offset(uint64_t offset) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->section_from_offset(offset));
}


const Section* Binary::section_from_rva(uint64_t virtual_address) const {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [virtual_address] (const std::unique_ptr<Section>& section) {
        return section->virtual_address() <= virtual_address &&
               virtual_address < (section->virtual_address() + section->virtual_size());
      });

  if (it_section == std::end(sections_)) {
    return nullptr;
  }


  return it_section->get();
}

Section* Binary::section_from_rva(uint64_t virtual_address) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->section_from_rva(virtual_address));
}



DataDirectory& Binary::data_directory(DATA_DIRECTORY index) {
  return const_cast<DataDirectory&>(static_cast<const Binary*>(this)->data_directory(index));
}

const DataDirectory& Binary::data_directory(DATA_DIRECTORY index) const {
  static const DataDirectory NONE;
  if (static_cast<size_t>(index) < data_directories_.size() &&
      data_directories_[static_cast<size_t>(index)] != nullptr) {
    return *data_directories_[static_cast<size_t>(index)];
  }
  LIEF_ERR("Index out of bound");
  return NONE;
}


bool Binary::has(DATA_DIRECTORY index) const {
  const auto it = std::find_if(std::begin(data_directories_), std::end(data_directories_),
                               [index] (const std::unique_ptr<DataDirectory>& d) {
                                  return d->type() == index;
                               });
  return it != std::end(data_directories_);
}

bool Binary::has_rich_header() const {
  return has_rich_header_;
}

bool Binary::has_tls() const {
  return has_tls_;
}

bool Binary::has_imports() const {
  return has_imports_;
}

bool Binary::has_signatures() const {
  return !signatures_.empty();
}

bool Binary::has_exports() const {
  return has_exports_;
}

bool Binary::has_resources() const {
  return has_resources_ && resources_ != nullptr;
}

bool Binary::has_exceptions() const {
  return has(DATA_DIRECTORY::EXCEPTION_TABLE);
}

bool Binary::has_relocations() const {
  return has_relocations_;
}

bool Binary::has_debug() const {
  return has_debug_;
}

bool Binary::is_reproducible_build() const {
  return is_reproducible_build_;
}

bool Binary::has_configuration() const {
  return has_configuration_ && load_configuration_ != nullptr;
}

const LoadConfiguration* Binary::load_configuration() const {
  if (!has_configuration()) {
    return nullptr;
  }
  return load_configuration_.get();
}

LoadConfiguration* Binary::load_configuration() {
  return const_cast<LoadConfiguration*>(static_cast<const Binary*>(this)->load_configuration());
}

//
// Interface with LIEF::Binary
//
LIEF::Binary::symbols_t Binary::get_abstract_symbols() {
  LIEF::Binary::symbols_t lief_symbols;
  for (Symbol& s : symbols_) {
    lief_symbols.push_back(&s);
  }

  for (ExportEntry& exp : export_.entries()) {
    lief_symbols.push_back(&exp);
  }

  for (Import& imp : imports_) {
    for (ImportEntry& entry : imp.entries()) {
      lief_symbols.push_back(&entry);
    }
  }

  for (DelayImport& imp : delay_imports_) {
    for (DelayImportEntry& entry : imp.entries()) {
      lief_symbols.push_back(&entry);
    }
  }
  return lief_symbols;
}


// Sections
// ========

Binary::it_sections Binary::sections() {
  return sections_;
}


Binary::it_const_sections Binary::sections() const {
  return sections_;
}

LIEF::Binary::sections_t Binary::get_abstract_sections() {
  LIEF::Binary::sections_t secs;
  secs.reserve(sections_.size());
  std::transform(std::begin(sections_), std::end(sections_),
                 std::back_inserter(secs),
                 [] (const std::unique_ptr<Section>& s) {
                  return s.get();
                 });
  return secs;
}


Section* Binary::get_section(const std::string& name) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->get_section(name));
}

const Section* Binary::get_section(const std::string& name) const {
  const auto section_it = std::find_if(std::begin(sections_), std::end(sections_),
      [&name] (const std::unique_ptr<Section>& section) {
        return section->name() == name;
      });

  if (section_it == std::end(sections_)) {
    return nullptr;
  }
  return section_it->get();
}


const Section* Binary::import_section() const {
  if (!has_imports()) {
    return nullptr;
  }
  const DataDirectory& import_directory = data_directory(DATA_DIRECTORY::IMPORT_TABLE);
  return import_directory.section();
}


Section* Binary::import_section() {
  return const_cast<Section*>(static_cast<const Binary*>(this)->import_section());
}

// Headers
// =======

// Dos Header
// ----------
DosHeader& Binary::dos_header() {
  return const_cast<DosHeader&>(static_cast<const Binary*>(this)->dos_header());
}


const DosHeader& Binary::dos_header() const {
  return dos_header_;
}


// Standard header
// ---------------
Header& Binary::header() {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}


const Header& Binary::header() const {
  return header_;
}

// Optional Header
// ---------------
const OptionalHeader& Binary::optional_header() const {
  return optional_header_;
}


OptionalHeader& Binary::optional_header() {
  return const_cast<OptionalHeader&>(static_cast<const Binary*>(this)->optional_header());
}




uint64_t Binary::virtual_size() const {
  uint64_t size = 0;
  size += dos_header().addressof_new_exeheader();
  size += sizeof(details::pe_header);
  if (type_ == PE_TYPE::PE32) {
    size += sizeof(details::pe32_optional_header);
  } else {
    size += sizeof(details::pe64_optional_header);
  }
  for (const std::unique_ptr<Section>& section : sections_) {
    size = std::max(size, section->virtual_address() + section->virtual_size());
  }
  size = LIEF::align(size, optional_header().section_alignment());
  return size;
}


uint32_t Binary::sizeof_headers() const {
  uint32_t size = 0;
  size += dos_header().addressof_new_exeheader();
  size += sizeof(details::pe_header);
  if (type_ == PE_TYPE::PE32) {
    size += sizeof(details::pe32_optional_header);
  } else {
    size += sizeof(details::pe64_optional_header);
  }

  size += sizeof(details::pe_data_directory) * data_directories_.size();
  size += sizeof(details::pe_section) * sections_.size();
  size = static_cast<uint32_t>(LIEF::align(size, optional_header().file_alignment()));
  return size;

}

void Binary::remove_section(const std::string& name, bool clear) {
  Section* sec = get_section(name);

  if (sec == nullptr) {
    LIEF_ERR("Unable to find the section: '{}'", name);
    return;
  }

  return remove(*sec, clear);
}


void Binary::remove(const Section& section, bool clear) {
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
      [&section] (const std::unique_ptr<Section>& s) {
        return *s == section;
      });

  if (it_section == std::end(sections_)) {
    LIEF_ERR("Unable to find section: '{}'", section.name());
    return;
  }

  std::unique_ptr<Section>& to_remove = *it_section;
  const size_t section_index = std::distance(std::begin(sections_), it_section);

  if (section_index < (sections_.size() - 1) && section_index > 0) {
    std::unique_ptr<Section>& previous = sections_[section_index - 1];
    const size_t raw_size_gap = (to_remove->offset() + to_remove->size()) - (previous->offset() + previous->size());
    previous->size(previous->size() + raw_size_gap);

    const size_t vsize_size_gap = (to_remove->virtual_address() + to_remove->virtual_size()) -
                                  (previous->virtual_address() + previous->virtual_size());
    previous->virtual_size(previous->virtual_size() + vsize_size_gap);
  }


  if (clear) {
    to_remove->clear(0);
  }

  sections_.erase(it_section);

  header().numberof_sections(header().numberof_sections() - 1);

  optional_header().sizeof_headers(sizeof_headers());
  optional_header().sizeof_image(static_cast<uint32_t>(virtual_size()));
}

void Binary::make_space_for_new_section() {
  const uint32_t shift = align(sizeof(details::pe_section), optional_header().file_alignment());
  LIEF_DEBUG("Making space for a new section header");
  LIEF_DEBUG("  -> Shifting all sections by 0x{:x}", shift);

  // Shift offset of the section content by the size of
  // a section header aligned on "file alignment"
  for (std::unique_ptr<Section>& section : sections_) {
    section->pointerto_raw_data(section->pointerto_raw_data() + shift);
  }
  available_sections_space_++;
}

Section* Binary::add_section(const Section& section, PE_SECTION_TYPES type) {

  if (available_sections_space_ < 0) {
    make_space_for_new_section();
    return add_section(section, type);
  }

  // Check if a section of type **type** already exist
  const auto it_section = std::find_if(std::begin(sections_), std::end(sections_),
                                       [&type] (const std::unique_ptr<Section>& s) {
                                         return s->is_type(type);
                                       });

  if (it_section != std::end(sections_)) {
    std::unique_ptr<Section>& s = *it_section;
    s->remove_type(type);
  }

  auto new_section                = std::make_unique<Section>(section);
  span<const uint8_t> content_ref = new_section->content();
  std::vector<uint8_t> content    = {std::begin(content_ref), std::end(content_ref)};
  const auto section_size         = static_cast<uint32_t>(content.size());
  const auto section_size_aligned = static_cast<uint32_t>(align(section_size, optional_header().file_alignment()));
  const uint32_t virtual_size     = section_size;

  content.insert(std::end(content), section_size_aligned - section_size, 0);
  new_section->content(content);

  // Compute new section offset
  uint64_t new_section_offset = align(std::accumulate(
      std::begin(sections_), std::end(sections_), static_cast<uint64_t>(sizeof_headers()),
      [] (uint64_t offset, const std::unique_ptr<Section>& s) {
        return std::max<uint64_t>(s->pointerto_raw_data() + s->sizeof_raw_data(), offset);
      }), optional_header().file_alignment());

  LIEF_DEBUG("New section offset: 0x{:x}", new_section_offset);


  // Compute new section Virtual address
  const uint64_t section_align = static_cast<uint64_t>(optional_header().section_alignment());
  const uint64_t new_section_va = align(std::accumulate(
      std::begin(sections_), std::end(sections_), section_align,
      [] (uint64_t va, const std::unique_ptr<Section>& s) {
        return std::max<uint64_t>(s->virtual_address() + s->virtual_size(), va);
      }), section_align);

  LIEF_DEBUG("New section VA: 0x{:x}", new_section_va);

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
    optional_header().baseof_code(static_cast<uint32_t>(new_section->virtual_address()));
    optional_header().sizeof_code(new_section->sizeof_raw_data());
  }

  if (new_section->is_type(PE_SECTION_TYPES::DATA)) {
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

    if (this->type() == PE_TYPE::PE32) {
      optional_header().baseof_data(static_cast<uint32_t>(new_section->virtual_address()));
    }
    optional_header().sizeof_initialized_data(new_section->sizeof_raw_data());
  }


  if (type == PE_SECTION_TYPES::IMPORT) {

    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
    new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

    data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA(new_section->virtual_address());
    data_directory(DATA_DIRECTORY::IMPORT_TABLE).size(new_section->sizeof_raw_data());
    data_directory(DATA_DIRECTORY::IMPORT_TABLE).section_ = new_section.get();
    data_directory(DATA_DIRECTORY::IAT).RVA(0);
    data_directory(DATA_DIRECTORY::IAT).size(0);
  }

  if (type == PE_SECTION_TYPES::RELOCATION) {
    data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA(new_section->virtual_address());
    data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size(new_section->virtual_size());
    data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).section_ = new_section.get();
  }

  if (type == PE_SECTION_TYPES::RESOURCE) {
    data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA(new_section->virtual_address());
    data_directory(DATA_DIRECTORY::RESOURCE_TABLE).size(new_section->size());
    data_directory(DATA_DIRECTORY::RESOURCE_TABLE).section_ = new_section.get();
  }

  if (type == PE_SECTION_TYPES::TLS) {
    data_directory(DATA_DIRECTORY::TLS_TABLE).RVA(new_section->virtual_address());
    data_directory(DATA_DIRECTORY::TLS_TABLE).size(new_section->size());
    data_directory(DATA_DIRECTORY::TLS_TABLE).section_ = new_section.get();
  }


  if (sections_.size() >= std::numeric_limits<uint16_t>::max()) {
    LIEF_INFO("Binary reachs its maximum number of sections");
    return nullptr;
  }

  available_sections_space_--;

  // Update headers
  header().numberof_sections(static_cast<uint16_t>(sections_.size()));

  optional_header().sizeof_image(this->virtual_size());
  optional_header().sizeof_headers(sizeof_headers());
  Section* sec = new_section.get();
  sections_.push_back(std::move(new_section));
  return sec;
}


//////////////////////////////////
//
// Methods to manage relocations
//
//////////////////////////////////

Binary::it_relocations Binary::relocations() {
  return relocations_;
}


Binary::it_const_relocations Binary::relocations() const {
  return relocations_;
}


Relocation& Binary::add_relocation(const Relocation& relocation) {
  auto newone = std::make_unique<Relocation>(relocation);
  relocations_.push_back(std::move(newone));
  return *relocations_.back();
}

void Binary::remove_all_relocations() {
  relocations_.clear();
}


LIEF::Binary::relocations_t Binary::get_abstract_relocations() {
  LIEF::Binary::relocations_t abstract_relocs;
  for (Relocation& relocation : relocations()) {
    for (RelocationEntry& entry : relocation.entries()) {
      abstract_relocs.push_back(&entry);
    }
  }
  return abstract_relocs;
}

// Imports
// =======

Binary::it_imports Binary::imports() {
  return imports_;
}

Binary::it_const_imports Binary::imports() const {
  return imports_;
}

ImportEntry* Binary::add_import_function(const std::string& library, const std::string& function) {
  const auto it_import = std::find_if(std::begin(imports_), std::end(imports_),
      [&library] (const Import& import) {
        return import.name() == library;
      });

  if (it_import == std::end(imports_)) {
    LIEF_ERR("The library doesn't exist");
    return nullptr;
  }

  it_import->add_entry({function});
  return it_import->get_entry(function);
}

Import& Binary::add_library(const std::string& name) {
  imports_.emplace_back(name);
  if (!imports_.empty()) {
    has_imports_ = true;
  }
  return imports_.back();
}

void Binary::remove_library(const std::string&) {
  LIEF_ERR("Removing a library from a PE file is not implemented yet");
}

void Binary::remove_all_libraries() {
  imports_.clear();
}

uint32_t Binary::predict_function_rva(const std::string& library, const std::string& function) {
  const auto it_import = std::find_if(imports_.cbegin(), imports_.cend(),
      [&library] (const Import& imp) {
        return imp.name() == library;
      });

  if (it_import == std::end(imports_)) {
    LIEF_ERR("Unable to find library {}", library);
    return 0;
  }

  Import::it_const_entries entries = it_import->entries();

  // Some weird library define a function twice
  size_t nb_functions = std::count_if(entries.cbegin(), entries.cend(),
      [&function](const ImportEntry& entry ) {
        return !entry.is_ordinal() && entry.name() == function;
      });

  if (nb_functions == 0) {
    LIEF_ERR("Unable to find the function '{}' in '{}'", function, library);
    return 0;
  }

  if (nb_functions > 1) {
    LIEF_ERR("{} is defined #{:d} times in {}", function, nb_functions, library);
    return 0;
  }

  uint32_t import_table_size = static_cast<uint32_t>((imports().size() + 1) * sizeof(details::pe_import)); // +1 for the null entry

  uint32_t address = import_table_size;

  uint32_t lookup_table_size = 0;
  for (const Import& f : imports_) {
    if (type_ == PE_TYPE::PE32) {
      lookup_table_size += (f.entries().size() + 1) * sizeof(uint32_t);
    } else {
      lookup_table_size += (f.entries().size() + 1) * sizeof(uint64_t);
    }
  }

  address += lookup_table_size;

  for (auto it_imp = imports_.cbegin();
      (it_imp->name() != library && it_imp != imports_.cend());
       ++it_imp) {
    if (type_ == PE_TYPE::PE32) {
      address += sizeof(uint32_t) * (it_imp->entries().size() + 1);
    } else {
      address += sizeof(uint64_t) * (it_imp->entries().size() + 1);
    }
  }


  for (auto it_func = entries.cbegin();
      (it_func->name() != function && it_func != entries.cend());
       ++it_func) {
    if (type_ == PE_TYPE::PE32) {
      address += sizeof(uint32_t);
    } else {
      address += sizeof(uint64_t);
    }
  }


  // We assume the the idata section will be the last section
  const uint64_t section_align = static_cast<uint64_t>(optional_header().section_alignment());
  const uint64_t next_virtual_address = align(std::accumulate(
      std::begin(sections_),
      std::end(sections_), section_align,
      [] (uint64_t va, const std::unique_ptr<Section>& s) {
        return std::max<uint64_t>(s->virtual_address() + s->virtual_size(), va);
      }), section_align);

  return next_virtual_address + address;
}


bool Binary::has_import(const std::string& import_name) const {
  return get_import(import_name) != nullptr;
}


Import* Binary::get_import(const std::string& import_name) {
  return const_cast<Import*>(static_cast<const Binary*>(this)->get_import(import_name));
}

const Import* Binary::get_import(const std::string& import_name) const {
  const auto it_import = std::find_if(std::begin(imports_), std::end(imports_),
      [&import_name] (const Import& import) {
        return import.name() == import_name;
      });

  if (it_import == std::end(imports_)) {
    return nullptr;
  }

  return &*it_import;
}


Export& Binary::get_export() {
  return const_cast<Export&>(static_cast<const Binary*>(this)->get_export());
}


const Export& Binary::get_export() const {
  return export_;
}

/////////////////////////////////////
//
// Methods to manage Resources
//
/////////////////////////////////////

void Binary::set_resources(const ResourceDirectory& resource) {
  resources_ = std::make_unique<ResourceDirectory>(resource);
}


void Binary::set_resources(const ResourceData& resource) {
  resources_ = std::make_unique<ResourceData>(resource);
}

ResourceNode* Binary::resources() {
  return const_cast<ResourceNode*>(static_cast<const Binary*>(this)->resources());
}

const ResourceNode* Binary::resources() const {
  return resources_.get();
}


/////////////////////////////////////
//
// Methods to manage DataDirectories
//
/////////////////////////////////////
Binary::it_data_directories Binary::data_directories() {
  return data_directories_;
}

Binary::it_const_data_directories Binary::data_directories() const {
  return data_directories_;
}


Binary::debug_entries_t& Binary::debug() {
  return const_cast<debug_entries_t&>(static_cast<const Binary*>(this)->debug());
}


const Binary::debug_entries_t& Binary::debug() const {
  return debug_;
}

/////////////////////
//
// Various methods
//
/////////////////////

Binary::it_const_signatures Binary::signatures() const {
  return signatures_;
}

std::vector<uint8_t> Binary::authentihash(ALGORITHMS algo) const {
  static const std::map<ALGORITHMS, hashstream::HASH> HMAP = {
    {ALGORITHMS::MD5,     hashstream::HASH::MD5},
    {ALGORITHMS::SHA_1,   hashstream::HASH::SHA1},
    {ALGORITHMS::SHA_256, hashstream::HASH::SHA256},
    {ALGORITHMS::SHA_384, hashstream::HASH::SHA384},
    {ALGORITHMS::SHA_512, hashstream::HASH::SHA512},
  };
  auto it_hash = HMAP.find(algo);
  if (it_hash == std::end(HMAP)) {
    LIEF_WARN("Unsupported hash algorithm: {}", to_string(algo));
    return {};
  }
  const size_t sizeof_ptr = type_ == PE_TYPE::PE32 ? sizeof(uint32_t) : sizeof(uint64_t);
  const hashstream::HASH hash_type = it_hash->second;
  hashstream ios(hash_type);
  //vector_iostream ios;
  ios // Hash dos header
    .write(dos_header_.magic())
    .write(dos_header_.used_bytes_in_the_last_page())
    .write(dos_header_.file_size_in_pages())
    .write(dos_header_.numberof_relocation())
    .write(dos_header_.header_size_in_paragraphs())
    .write(dos_header_.minimum_extra_paragraphs())
    .write(dos_header_.maximum_extra_paragraphs())
    .write(dos_header_.initial_relative_ss())
    .write(dos_header_.initial_sp())
    .write(dos_header_.checksum())
    .write(dos_header_.initial_ip())
    .write(dos_header_.initial_relative_cs())
    .write(dos_header_.addressof_relocation_table())
    .write(dos_header_.overlay_number())
    .write(dos_header_.reserved())
    .write(dos_header_.oem_id())
    .write(dos_header_.oem_info())
    .write(dos_header_.reserved2())
    .write(dos_header_.addressof_new_exeheader())
    .write(dos_stub_);

  ios // Hash PE Header
    .write(header_.signature())
    .write(static_cast<uint16_t>(header_.machine()))
    .write(header_.numberof_sections())
    .write(header_.time_date_stamp())
    .write(header_.pointerto_symbol_table())
    .write(header_.numberof_symbols())
    .write(header_.sizeof_optional_header())
    .write(static_cast<uint16_t>(header_.characteristics()));

  ios // Hash OptionalHeader
    .write(static_cast<uint16_t>(optional_header_.magic()))
    .write(optional_header_.major_linker_version())
    .write(optional_header_.minor_linker_version())
    .write(optional_header_.sizeof_code())
    .write(optional_header_.sizeof_initialized_data())
    .write(optional_header_.sizeof_uninitialized_data())
    .write(optional_header_.addressof_entrypoint())
    .write(optional_header_.baseof_code());

  if (type_ == PE_TYPE::PE32) {
    ios.write(optional_header_.baseof_data());
  }
  ios // Continuation of optional header
    .write_sized_int(optional_header_.imagebase(), sizeof_ptr)
    .write(optional_header_.section_alignment())
    .write(optional_header_.file_alignment())
    .write(optional_header_.major_operating_system_version())
    .write(optional_header_.minor_operating_system_version())
    .write(optional_header_.major_image_version())
    .write(optional_header_.minor_image_version())
    .write(optional_header_.major_subsystem_version())
    .write(optional_header_.minor_subsystem_version())
    .write(optional_header_.win32_version_value())
    .write(optional_header_.sizeof_image())
    .write(optional_header_.sizeof_headers())
    // optional_header_.checksum()) is not a part of the hash
    .write(static_cast<uint16_t>(optional_header_.subsystem()))
    .write(static_cast<uint16_t>(optional_header_.dll_characteristics()))
    .write_sized_int(optional_header_.sizeof_stack_reserve(), sizeof_ptr)
    .write_sized_int(optional_header_.sizeof_stack_commit(), sizeof_ptr)
    .write_sized_int(optional_header_.sizeof_heap_reserve(), sizeof_ptr)
    .write_sized_int(optional_header_.sizeof_heap_commit(), sizeof_ptr)
    .write(optional_header_.loader_flags())
    .write(optional_header_.numberof_rva_and_size());

  for (const std::unique_ptr<DataDirectory>& dir : data_directories_) {
    if (dir->type() == DATA_DIRECTORY::CERTIFICATE_TABLE) {
      continue;
    }
    ios
      .write(dir->RVA())
      .write(dir->size());
  }

  for (const std::unique_ptr<Section>& sec : sections_) {
    std::array<char, 8> name = {0};
    const std::string& sec_name = sec->fullname();
    uint32_t name_length = std::min<uint32_t>(sec_name.size() + 1, sizeof(name));
    std::copy(sec_name.c_str(), sec_name.c_str() + name_length, std::begin(name));
    ios
      .write(name)
      .write(sec->virtual_size())
      .write<uint32_t>(sec->virtual_address())
      .write(sec->sizeof_raw_data())
      .write(sec->pointerto_raw_data())
      .write(sec->pointerto_relocation())
      .write(sec->pointerto_line_numbers())
      .write(sec->numberof_relocations())
      .write(sec->numberof_line_numbers())
      .write(static_cast<uint32_t>(sec->characteristics()));
  }
  //LIEF_DEBUG("Section padding at 0x{:x}", ios.tellp());
  ios.write(section_offset_padding_);

  std::vector<Section*> sections;
  sections.reserve(sections_.size());
  std::transform(std::begin(sections_), std::end(sections_),
                 std::back_inserter(sections),
                 [] (const std::unique_ptr<Section>& s) {
                   return s.get();
                 });

  // Sort by file offset
  std::sort(std::begin(sections), std::end(sections),
            [] (const Section* lhs, const Section* rhs) {
              return  lhs->pointerto_raw_data() < rhs->pointerto_raw_data();
            });

  uint64_t position = 0;
  for (const Section* sec : sections) {
    if (sec->sizeof_raw_data() == 0) {
      continue;
    }
    const std::vector<uint8_t>& pad     = sec->padding();
    span<const uint8_t> content = sec->content();
    LIEF_DEBUG("Authentihash:  Append section {:<8}: [0x{:04x}, 0x{:04x}] + [0x{:04x}] = [0x{:04x}, 0x{:04x}]",
               sec->name(),
               sec->offset(), sec->offset() + content.size(), pad.size(),
               sec->offset(), sec->offset() + content.size() + pad.size());
    if (/* overlapping */ sec->offset() < position) {
      // Trunc the beginning of the overlap
      if (position <= sec->offset() + content.size()) {
        const uint64_t start_p = position - sec->offset();
        const uint64_t size = content.size() - start_p;
        ios
          .write(content.data() + start_p, size)
          .write(pad);
      } else {
        LIEF_WARN("Overlapping in the padding area");
      }
    } else {
      ios
        .write(content.data(), content.size())
        .write(pad);
    }
    position = sec->offset() + content.size() + pad.size();
  }
  if (!overlay_.empty()) {
    const DataDirectory& cert_dir = data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE);
    LIEF_DEBUG("Add overlay and omit 0x{:08x} - 0x{:08x}", cert_dir.RVA(), cert_dir.RVA() + cert_dir.size());
    if (cert_dir.RVA() > 0 && cert_dir.size() > 0 && cert_dir.RVA() >= overlay_offset_) {
      const uint64_t start_cert_offset = cert_dir.RVA() - overlay_offset_;
      const uint64_t end_cert_offset   = start_cert_offset + cert_dir.size();
      if (end_cert_offset <= overlay_.size()) {
        LIEF_DEBUG("Add [0x{:x}, 0x{:x}]", overlay_offset_, overlay_offset_ + start_cert_offset);
        LIEF_DEBUG("Add [0x{:x}, 0x{:x}]",
                   overlay_offset_ + end_cert_offset,
                   overlay_offset_ + overlay_.size() - end_cert_offset);
        ios
          .write(overlay_.data(), start_cert_offset)
          .write(overlay_.data() + end_cert_offset, overlay_.size() - end_cert_offset);
      } else {
        ios.write(overlay());
      }
    } else {
      ios.write(overlay());
    }
  }
  // When something gets wrong with the hash:
  // std::vector<uint8_t> out = ios.raw();
  // std::ofstream output_file{"/tmp/hash.blob", std::ios::out | std::ios::binary | std::ios::trunc};
  // if (output_file) {
  //   std::copy(
  //       std::begin(out),
  //       std::end(out),
  //       std::ostreambuf_iterator<char>(output_file));
  // }
  // std::vector<uint8_t> hash = hashstream(hash_type).write(out).raw();

  std::vector<uint8_t> hash = ios.raw();
  LIEF_DEBUG("{}", hex_dump(hash));
  return hash;
}

Signature::VERIFICATION_FLAGS Binary::verify_signature(Signature::VERIFICATION_CHECKS checks) const {
  if (!has_signatures()) {
    return Signature::VERIFICATION_FLAGS::NO_SIGNATURE;
  }

  Signature::VERIFICATION_FLAGS flags = Signature::VERIFICATION_FLAGS::OK;

  for (size_t i = 0; i < signatures_.size(); ++i) {
    const Signature& sig = signatures_[i];
    flags |= verify_signature(sig, checks);
    if (flags != Signature::VERIFICATION_FLAGS::OK) {
      LIEF_INFO("Verification failed for signature #{:d} (0b{:b})", i, static_cast<uintptr_t>(flags));
      break;
    }
  }
  return flags;
}

Signature::VERIFICATION_FLAGS Binary::verify_signature(const Signature& sig, Signature::VERIFICATION_CHECKS checks) const {
  Signature::VERIFICATION_FLAGS flags = Signature::VERIFICATION_FLAGS::OK;
  if (!is_true(checks & Signature::VERIFICATION_CHECKS::HASH_ONLY)) {
    const Signature::VERIFICATION_FLAGS value = sig.check(checks);
    if (value != Signature::VERIFICATION_FLAGS::OK) {
      LIEF_INFO("Bad signature (0b{:b})", static_cast<uintptr_t>(value));
      flags |= value;
    }
  }

  // Check that the authentihash matches Content Info's digest
  const std::vector<uint8_t>& authhash = authentihash(sig.digest_algorithm());
  const std::vector<uint8_t>& chash = sig.content_info().digest();
  if (authhash != chash) {
    LIEF_INFO("Authentihash and Content info's digest does not match:\n  {}\n  {}",
              hex_dump(authhash), hex_dump(chash));
    flags |= Signature::VERIFICATION_FLAGS::BAD_DIGEST;
  }
  if (flags != Signature::VERIFICATION_FLAGS::OK) {
    flags |= Signature::VERIFICATION_FLAGS::BAD_SIGNATURE;
  }
return flags;
}


std::vector<Symbol>& Binary::symbols() {
  return const_cast<std::vector<Symbol>&>(static_cast<const Binary*>(this)->symbols());
}


const std::vector<Symbol>& Binary::symbols() const {
  return symbols_;
}


LIEF::Binary::functions_t Binary::get_abstract_exported_functions() const {
  LIEF::Binary::functions_t result;
  if (has_exports()) {
    for (const ExportEntry& entry : get_export().entries()) {
      const std::string& name = entry.name();
      if(!name.empty()) {
        result.emplace_back(name, entry.address(), Function::flags_list_t{Function::FLAGS::EXPORTED});
      }
    }
  }
  return result;
}

LIEF::Binary::functions_t Binary::get_abstract_imported_functions() const {
  LIEF::Binary::functions_t result;
  for (const Import& import : imports()) {
    Import resolved = import;
    if (auto resolution = resolve_ordinals(import)) {
      resolved = std::move(*resolution);
    }
    for (const ImportEntry& entry : resolved.entries()) {
      const std::string& name = entry.name();
      if(!name.empty()) {
        result.emplace_back(name, entry.iat_address(),
                            Function::flags_list_t{Function::FLAGS::IMPORTED});
      }
    }
  }


  for (const DelayImport& import : delay_imports()) {
    for (const DelayImportEntry& entry : import.entries()) {
      if (entry.is_ordinal()) {
        continue;
      }
      const std::string& name = entry.name();
      if(!name.empty()) {
        result.emplace_back(name, entry.value(),
                            Function::flags_list_t{Function::FLAGS::IMPORTED});
      }
    }
  }
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_libraries() const {
  std::vector<std::string> result;
  for (const Import& import : imports()) {
    result.push_back(import.name());
  }
  for (const DelayImport& import : delay_imports()) {
    result.push_back(import.name());
  }
  return result;
}

LIEF::Header Binary::get_abstract_header() const {
  LIEF::Header header;

  const MACHINE_TYPES machine = this->header().machine();
  auto it_arch = arch_pe_to_lief.find(machine);
  if (it_arch == std::end(arch_pe_to_lief)) {
    LIEF_ERR("Can't abstract the architecture {}", to_string(machine));
    header.architecture(ARCHITECTURES::ARCH_NONE);
    header.modes({});
  } else {
    const auto& p = it_arch->second;
    header.architecture(p.first);
    header.modes(p.second);
  }


  header.entrypoint(entrypoint());

  if (this->header().has_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_DLL)) {
    header.object_type(OBJECT_TYPES::TYPE_LIBRARY);
  } else if (this->header().has_characteristic(HEADER_CHARACTERISTICS::IMAGE_FILE_EXECUTABLE_IMAGE)) {
    header.object_type(OBJECT_TYPES::TYPE_EXECUTABLE);
  } else {
    header.object_type(OBJECT_TYPES::TYPE_NONE);
  }

  auto it_endi = arch_pe_to_endi_lief.find(machine);

  if (it_endi == std::end(arch_pe_to_endi_lief)) {
    LIEF_ERR("Can't find the endianness for {}", to_string(machine));
    header.endianness(ENDIANNESS::ENDIAN_NONE);
  } else {
    header.endianness(it_endi->second);
  }

  return header;
}



void Binary::hook_function(const std::string& function, uint64_t address) {

  for (const Import& import : imports_) {
    for (const ImportEntry& import_entry : import.entries()) {
      if (import_entry.name() == function) {
        return hook_function(import.name(), function, address);
      }
    }
  }

  LIEF_WARN("Unable to find library associated with function '{}'", function);
}


void Binary::hook_function(const std::string& library, const std::string& function, uint64_t address) {
  hooks_[library][function] = address;
}

// LIEF Interface
// ==============
uint64_t Binary::entrypoint() const {
  return optional_header().imagebase() + optional_header().addressof_entrypoint();
}

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES addr_type) {
  uint64_t rva = address;

  if (addr_type == LIEF::Binary::VA_TYPES::VA || addr_type == LIEF::Binary::VA_TYPES::AUTO) {
    const int64_t delta = address - optional_header().imagebase();

    if (delta > 0 || addr_type == LIEF::Binary::VA_TYPES::VA) {
      rva -= optional_header().imagebase();
    }
  }

  // Find the section associated with the virtual address
  Section* section_topatch = section_from_rva(rva);
  if (section_topatch == nullptr) {
    LIEF_ERR("Can't find section with the rva: 0x{:x}", rva);
    return;
  }
  const uint64_t offset = rva - section_topatch->virtual_address();

  span<uint8_t> content = section_topatch->writable_content();
  if (offset + patch_value.size() > content.size()) {
    LIEF_ERR("The patch value ({} bytes @0x{:x}) is out of bounds of the section (limit: 0x{:x})",
             patch_value.size(), offset, content.size());
    return;
  }
  std::copy(std::begin(patch_value), std::end(patch_value),
            content.data() + offset);

}

void Binary::patch_address(uint64_t address, uint64_t patch_value,
                           size_t size, LIEF::Binary::VA_TYPES addr_type) {
  if (size > sizeof(patch_value)) {
    LIEF_ERR("Invalid size (0x{:x})", size);
    return;
  }

  uint64_t rva = address;

  if (addr_type == LIEF::Binary::VA_TYPES::VA || addr_type == LIEF::Binary::VA_TYPES::AUTO) {
    const int64_t delta = address - optional_header().imagebase();

    if (delta > 0 || addr_type == LIEF::Binary::VA_TYPES::VA) {
      rva -= optional_header().imagebase();
    }
  }

  Section* section_topatch = section_from_rva(rva);
  if (section_topatch == nullptr) {
    LIEF_ERR("Can't find section with the rva: 0x{:x}", rva);
    return;
  }
  const uint64_t offset = rva - section_topatch->virtual_address();
  span<uint8_t> content = section_topatch->writable_content();
  if (offset > content.size() || (offset + size) > content.size()) {
    LIEF_ERR("The patch value ({} bytes @0x{:x}) is out of bounds of the section (limit: 0x{:x})",
             size, offset, content.size());
  }
  switch (size) {
    case sizeof(uint8_t):
      {
        auto X = static_cast<uint8_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint8_t));
        break;
      }

    case sizeof(uint16_t):
      {
        auto X = static_cast<uint16_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint16_t));
        break;
      }

    case sizeof(uint32_t):
      {
        auto X = static_cast<uint32_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint32_t));
        break;
      }

    case sizeof(uint64_t):
      {
        auto X = static_cast<uint64_t>(patch_value);
        memcpy(content.data() + offset, &X, sizeof(uint64_t));
        break;
      }

    default:
      {
        LIEF_ERR("The provided size ({}) does not match the size of an integer", size);
        return;
      }
  }
}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address,
    uint64_t size, LIEF::Binary::VA_TYPES addr_type) const {

  uint64_t rva = virtual_address;

  if (addr_type == LIEF::Binary::VA_TYPES::VA || addr_type == LIEF::Binary::VA_TYPES::AUTO) {
    const int64_t delta = virtual_address - optional_header().imagebase();

    if (delta > 0 || addr_type == LIEF::Binary::VA_TYPES::VA) {
      rva -= optional_header().imagebase();
    }
  }
  const Section* section = section_from_rva(rva);
  if (section == nullptr) {
    LIEF_ERR("Can't find the section with the rva 0x{:x}", rva);
    return {};
  }
  span<const uint8_t> content = section->content();
  const uint64_t offset = rva - section->virtual_address();
  uint64_t checked_size = size;
  if ((offset + checked_size) > content.size()) {
    uint64_t delta_off = offset + checked_size - content.size();
    if (checked_size < delta_off) {
        LIEF_ERR("Can't access section data due to a section end overflow.");
        return {};
    }
    checked_size = checked_size - delta_off;
  }

  return {content.data() + offset, content.data() + offset + checked_size};

}

bool Binary::is_pie() const {
  return optional_header().has(DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
}

bool Binary::has_nx() const {
  return optional_header().has(DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);
}

// Overlay
// =======

const std::vector<uint8_t>& Binary::overlay() const {
  return overlay_;
}

std::vector<uint8_t>& Binary::overlay() {
  return overlay_;
}

// Dos stub
// ========

const std::vector<uint8_t>& Binary::dos_stub() const {
  return dos_stub_;
}

std::vector<uint8_t>& Binary::dos_stub() {
  return dos_stub_;
}


void Binary::dos_stub(const std::vector<uint8_t>& content) {
  dos_stub_ = content;
}

// Rich Header
// -----------
RichHeader& Binary::rich_header() {
  return rich_header_;
}

const RichHeader& Binary::rich_header() const {
  return rich_header_;
}

void Binary::rich_header(const RichHeader& rich_header) {
  rich_header_ = rich_header;
  has_rich_header_ = true;
}

// Resource manager
// ===============

result<ResourcesManager> Binary::resources_manager() const {
  if (resources_ == nullptr || !has_resources()) {
    return make_error_code(lief_errors::not_found);
  }
  return ResourcesManager{*resources_};
}

LIEF::Binary::functions_t Binary::ctor_functions() const {
  LIEF::Binary::functions_t functions;

  if (has_tls()) {
    const std::vector<uint64_t>& clbs = tls().callbacks();
    for (size_t i = 0; i < clbs.size(); ++i) {
      functions.emplace_back("tls_" + std::to_string(i), clbs[i],
                             Function::flags_list_t{Function::FLAGS::CONSTRUCTOR});

    }
  }
  return functions;
}


LIEF::Binary::functions_t Binary::functions() const {

  static const auto func_cmd = [] (const Function& lhs, const Function& rhs) {
    return lhs.address() < rhs.address();
  };
  std::set<Function, decltype(func_cmd)> functions_set(func_cmd);

  LIEF::Binary::functions_t exception_functions = this->exception_functions();
  LIEF::Binary::functions_t exported            = get_abstract_exported_functions();
  LIEF::Binary::functions_t ctors               = ctor_functions();

  std::move(std::begin(exception_functions), std::end(exception_functions),
            std::inserter(functions_set, std::end(functions_set)));

  std::move(std::begin(exported), std::end(exported),
            std::inserter(functions_set, std::end(functions_set)));

  std::move(std::begin(ctors), std::end(ctors),
            std::inserter(functions_set, std::end(functions_set)));

  return {std::begin(functions_set), std::end(functions_set)};
}

LIEF::Binary::functions_t Binary::exception_functions() const {
  LIEF::Binary::functions_t functions;
  if (!has_exceptions()) {
    return functions;
  }


  const DataDirectory& exception_dir = data_directory(DATA_DIRECTORY::EXCEPTION_TABLE);
  std::vector<uint8_t> exception_data = get_content_from_virtual_address(exception_dir.RVA(), exception_dir.size());
  VectorStream vs{std::move(exception_data)};
  const size_t nb_entries = vs.size() / sizeof(details::pe_exception_entry_x64); // TODO: Handle other architectures

  for (size_t i = 0; i < nb_entries; ++i) {
    auto res_entry = vs.read<details::pe_exception_entry_x64>();
    if (!res_entry) {
      LIEF_ERR("Can't read entry #{:02d}", i);
      break;
    }
    auto entry = *res_entry;
    Function f{entry.address_start_rva};
    if (entry.address_end_rva > entry.address_start_rva) {
      f.size(entry.address_end_rva - entry.address_start_rva);
    }
    functions.push_back(std::move(f));
  }

  return functions;
}


// Delay Imports
// ========================================================
bool Binary::has_delay_imports() const {
  return !delay_imports_.empty();
}

Binary::it_delay_imports Binary::delay_imports() {
  return delay_imports_;
}

Binary::it_const_delay_imports Binary::delay_imports() const {
  return delay_imports_;
}


DelayImport* Binary::get_delay_import(const std::string& import_name) {
  return const_cast<DelayImport*>(static_cast<const Binary*>(this)->get_delay_import(import_name));
}

const DelayImport* Binary::get_delay_import(const std::string& import_name) const {
  const auto it_import = std::find_if(std::begin(delay_imports_), std::end(delay_imports_),
      [&import_name] (const DelayImport& import) {
        return import.name() == import_name;
      });

  if (it_import == std::end(delay_imports_)) {
    return nullptr;
  }

  return &*it_import;
}

bool Binary::has_delay_import(const std::string& import_name) const {
  return get_delay_import(import_name) != nullptr;
}

void Binary::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool Binary::operator==(const Binary& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool Binary::operator!=(const Binary& rhs) const {
  return !(*this == rhs);
}


std::ostream& Binary::print(std::ostream& os) const {

  os << "Dos Header" << std::endl;
  os << "==========" << std::endl;

  os << dos_header();
  os << std::endl;


  if (has_rich_header()) {
    os << "Rich Header" << std::endl;
    os << "===========" << std::endl;
    os << rich_header() << std::endl;
    os << std::endl;
  }


  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << header();
  os << std::endl;


  os << "Optional Header" << std::endl;
  os << "===============" << std::endl;

  os << optional_header();
  os << std::endl;


  os << "Data directories" << std::endl;
  os << "================" << std::endl;

  for (const DataDirectory& data_directory : data_directories()) {
    os << data_directory << std::endl;
  }
  os << std::endl;


  os << "Sections" << std::endl;
  os << "========" << std::endl;

  for (const Section& section : sections()) {
    os << section << std::endl;;
  }
  os << std::endl;


  if (has_tls()) {
    os << "TLS" << std::endl;
    os << "===" << std::endl;
    os << tls() << std::endl;
    os << std::endl;
  }


  if (has_signatures()) {
    os << "Signatures" << std::endl;
    os << "==========" << std::endl;
    for (const Signature& sig : signatures_) {
      os << sig << std::endl;
    }
    os << std::endl;
  }


  if (has_imports()) {
    os << "Imports" << std::endl;
    os << "=======" << std::endl;
    for (const Import& import : imports()) {
      os << import << std::endl;
    }
    os << std::endl;
  }

  if (has_delay_imports()) {
    os << "Delay Imports" << std::endl;
    os << "=============" << std::endl;
    for (const DelayImport& import : delay_imports()) {
      os << import << std::endl;
    }
    os << std::endl;
  }


  if (has_debug()) {
    os << "Debug" << std::endl;
    os << "=====" << std::endl;
    for (const Debug& debug : debug()) {
      os << debug << std::endl;
    }
    os << std::endl;
  }


  if (has_relocations()) {
    os << "Relocations" << std::endl;
    os << "===========" << std::endl;
    for (const Relocation& relocation : relocations()) {
      os << relocation << std::endl;
    }
    os << std::endl;
  }


  if (has_exports()) {
    os << "Export" << std::endl;
    os << "======" << std::endl;
    os << get_export() << std::endl;
    os << std::endl;
  }


  if (has_resources()) {
    if (auto manager = resources_manager()) {
      os << "Resources" << std::endl;
      os << "=========" << std::endl;
      os << *manager << std::endl;
      os << std::endl;
    }
  }

  os << "Symbols" << std::endl;
  os << "=======" << std::endl;

  for (const Symbol& symbol : symbols()) {
    os << symbol << std::endl;;
  }
  os << std::endl;


  if (has_configuration()) {
    os << "Load Configuration" << std::endl;
    os << "==================" << std::endl;

    os << load_configuration();

    os << std::endl;
  }



  return os;
}

} // namesapce PE
} // namespace LIEF
