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
#include <fstream>
#include <iterator>
#include <iostream>
#include <string>
#include <numeric>

#include <mbedtls/platform.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "filesystem/filesystem.h"

#include "logging.hpp"

#include "LIEF/exception.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/Abstract/Relocation.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/CodeViewPDB.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/ExportEntry.hpp"
#include "LIEF/PE/Pogo.hpp"
#include "LIEF/PE/PogoEntry.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/PE/EnumToString.hpp"

#include "signature/pkcs7.h"
#include "Parser.tcc"

// Issue with VS2017
#if defined(IMAGE_FILE_MACHINE_UNKNOWN)
#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#endif

namespace LIEF {
namespace PE {

Parser::~Parser(void) = default;
Parser::Parser(void) = default;

//
// CTOR
//
Parser::Parser(const std::string& file) :
  LIEF::Parser{file}
{

  if (not is_pe(file)) {
    throw LIEF::bad_format("'" + file + "' is not an PE");
  }

  // Read from file
  this->stream_ = std::unique_ptr<VectorStream>(new VectorStream{file});
  this->init(filesystem::path(file).filename());
}

Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  stream_{std::unique_ptr<VectorStream>(new VectorStream{data})}
{
  this->init(name);
}


void Parser::init(const std::string& name) {

  this->type_   = get_type(this->stream_->content());
  this->binary_ = new Binary{};
  this->binary_->name(name);
  this->binary_->type_ = this->type_;

  if (this->type_ == PE_TYPE::PE32) {
    this->parse<PE32>();
  } else {
    this->parse<PE64>();
  }

}

void Parser::parse_dos_stub(void) {
  const DosHeader& dos_header = this->binary_->dos_header();

  if (dos_header.addressof_new_exeheader() < sizeof(pe_dos_header)) {
    return;
  }
  const uint64_t sizeof_dos_stub = dos_header.addressof_new_exeheader() - sizeof(pe_dos_header);

  LIEF_DEBUG("DOS stub: @0x{:x}:0x{:x}", sizeof(pe_dos_header), sizeof_dos_stub);

  const uint8_t* ptr_to_dos_stub = this->stream_->peek_array<uint8_t>(sizeof(pe_dos_header), sizeof_dos_stub, /* check */false);
  if (ptr_to_dos_stub == nullptr) {
    LIEF_ERR("DOS stub is corrupted!");
  } else {
    this->binary_->dos_stub_ = {ptr_to_dos_stub, ptr_to_dos_stub + sizeof_dos_stub};
  }
}


void Parser::parse_rich_header(void) {
  LIEF_DEBUG("Parsing rich header");
  const std::vector<uint8_t>& dos_stub = this->binary_->dos_stub();
  VectorStream stream{dos_stub};
  auto&& it_rich = std::search(
      std::begin(dos_stub),
      std::end(dos_stub),
      std::begin(Rich_Magic),
      std::end(Rich_Magic));

  if (it_rich == std::end(dos_stub)) {
    LIEF_DEBUG("Rich header not found!");
    return;
  }


  const uint64_t end_offset_rich_header = std::distance(std::begin(dos_stub), it_rich);
  LIEF_DEBUG("Offset to rich header: 0x{:x}", end_offset_rich_header);

  if (not stream.can_read<uint32_t>(end_offset_rich_header + sizeof(Rich_Magic))) {
    return;
  }
  const uint32_t xor_key = stream.peek<uint32_t>(end_offset_rich_header + sizeof(Rich_Magic));

  this->binary_->rich_header().key(xor_key);
  LIEF_DEBUG("XOR key: 0x{:x}", xor_key);


  uint64_t curent_offset = end_offset_rich_header - sizeof(Rich_Magic);

  std::vector<uint32_t> values;
  values.reserve(dos_stub.size() / sizeof(uint32_t));

  uint32_t count = 0;
  uint32_t value = 0;

  while (value != DanS_Magic_number and count != DanS_Magic_number) {
    if (not stream.can_read<uint32_t>(curent_offset)) {
      break;
    }

    count = stream.peek<uint32_t>(curent_offset) ^ xor_key;
    curent_offset -= sizeof(uint32_t);

    if (not stream.can_read<uint32_t>(curent_offset)) {
      break;
    }

    value = stream.peek<uint32_t>(curent_offset) ^ xor_key;
    curent_offset -= sizeof(uint32_t);

    if (value == DanS_Magic_number or count == DanS_Magic_number) {
      break;
    }

    uint16_t build_number = value & 0xFFFF;
    uint16_t id           = (value >> 16) & 0xFFFF;

    LIEF_DEBUG("ID:           0x{:04x}", id);
    LIEF_DEBUG("Build Number: 0x{:04x}", build_number);
    LIEF_DEBUG("Count:        0x{:d}", count);

    this->binary_->rich_header().add_entry(id, build_number, count);
  }

  this->binary_->has_rich_header_ = true;

}




//
// parse PE sections
//
// TODO: Check offset etc
void Parser::parse_sections(void) {

  LIEF_DEBUG("Parsing sections");
  const uint32_t sections_offset  =
    this->binary_->dos_header().addressof_new_exeheader() +
    sizeof(pe_header) +
    this->binary_->header().sizeof_optional_header();

  uint32_t first_section_offset = -1u;

  const uint32_t numberof_sections = this->binary_->header().numberof_sections();
  const pe_section* sections = this->stream_->peek_array<pe_section>(sections_offset, numberof_sections, /* check */false);
  if (sections == nullptr) {
    LIEF_ERR("Section headers corrupted!");
    return;
  }

  for (size_t i = 0; i < numberof_sections; ++i) {
    std::unique_ptr<Section> section{new Section{&sections[i]}};

    uint32_t size_to_read = 0;
    uint32_t offset = sections[i].PointerToRawData;
    if (offset > 0) {
      first_section_offset = std::min(first_section_offset, offset);
    }

    if (sections[i].VirtualSize > 0) {
      size_to_read = std::min(sections[i].VirtualSize, sections[i].SizeOfRawData); // According to Corkami
    } else {
      size_to_read = sections[i].SizeOfRawData;
    }

    if ((offset + size_to_read) > this->stream_->size()) {
      uint32_t delta = (offset + size_to_read) - this->stream_->size();
      size_to_read = size_to_read - delta;
    }


    if (size_to_read > Parser::MAX_DATA_SIZE) {
      LIEF_WARN("Data of section section '{}' is too large (0x{:x})", section->name(), size_to_read);
    } else {
      const uint8_t* ptr_to_rawdata = this->stream_->peek_array<uint8_t>(offset, size_to_read, /* check */false);
      if (ptr_to_rawdata == nullptr) {
        LIEF_ERR("Section #{:d} ({}) is corrupted", i, section->name());
      } else {
        section->content_ = {
          ptr_to_rawdata,
          ptr_to_rawdata + size_to_read
        };
      }
      const uint64_t padding_size = section->size() - size_to_read;
      const uint8_t* ptr_to_padding = this->stream_->peek_array<uint8_t>(offset + size_to_read, padding_size, /* check */false);
      if (ptr_to_padding != nullptr) {
        section->padding_ = {ptr_to_padding, ptr_to_padding + padding_size};
      }
    }
    this->binary_->sections_.push_back(section.release());
  }

  const uint32_t last_section_header_offset = sections_offset + numberof_sections * sizeof(pe_section);
  const size_t padding_size = first_section_offset - last_section_header_offset;
  const uint8_t* padding_ptr = this->stream_->peek_array<uint8_t>(last_section_header_offset, padding_size,
                                                                  /* check */ false);
  if (padding_ptr != nullptr) {
    this->binary_->section_offset_padding_ = {padding_ptr, padding_ptr + padding_size};
  }
  this->binary_->available_sections_space_ = (first_section_offset - last_section_header_offset) / sizeof(pe_section) - 1;
  LIEF_DEBUG("Number of sections that could be added: #{:d}", this->binary_->available_sections_space_);
}


//
// parse relocations
//
void Parser::parse_relocations(void) {
  LIEF_DEBUG("== Parsing relocations ==");

  const uint32_t offset = this->binary_->rva_to_offset(
      this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA());

  const uint32_t max_size = this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size();
  const uint32_t max_offset = offset + max_size;

  if (not this->stream_->can_read<pe_base_relocation_block>(offset)) {
    return;
  }

  pe_base_relocation_block relocation_headers = this->stream_->peek<pe_base_relocation_block>(offset);

  uint32_t current_offset = offset;
  while (current_offset < max_offset and relocation_headers.PageRVA != 0) {
    std::unique_ptr<Relocation> relocation{new Relocation{&relocation_headers}};

    if (relocation_headers.BlockSize < sizeof(pe_base_relocation_block)) {
      LIEF_ERR("Relocation corrupted: BlockSize is too small");
      break;
    } else if (relocation_headers.BlockSize > this->binary_->optional_header().sizeof_image()) {
      LIEF_ERR("Relocation corrupted: BlockSize is out of bound the binary's virtual size");
      break;
    }

    const uint32_t numberof_entries = (relocation_headers.BlockSize - sizeof(pe_base_relocation_block)) / sizeof(uint16_t);
    const uint16_t* entries = this->stream_->peek_array<uint16_t>(current_offset + sizeof(pe_base_relocation_block), numberof_entries, /* check */false);

    if (entries == nullptr) {
      break;
    }

    for (size_t i = 0; i < numberof_entries; ++i) {
      std::unique_ptr<RelocationEntry> entry{new RelocationEntry{entries[i]}};
      entry->relocation_ = relocation.get();
      relocation->entries_.push_back(entry.release());
    }

    this->binary_->relocations_.push_back(relocation.release());

    current_offset += relocation_headers.BlockSize;

    relocation_headers = this->stream_->peek<pe_base_relocation_block>(current_offset);
  }

  this->binary_->has_relocations_ = true;
}


//
// parse ressources
//
void Parser::parse_resources(void) {
  LIEF_DEBUG("== Parsing resources ==");

  const uint32_t resources_rva = this->binary_->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA();
  LIEF_DEBUG("Resources RVA: 0x{:04x}", resources_rva);

  const uint32_t offset = this->binary_->rva_to_offset(resources_rva);
  LIEF_DEBUG("Resources Offset: 0x{:04x}", offset);

  if (not this->stream_->can_read<pe_resource_directory_table>(offset)) {
    return;
  }

  const pe_resource_directory_table& directory_table = this->stream_->peek<pe_resource_directory_table>(offset);

  this->binary_->resources_     = this->parse_resource_node(&directory_table, offset, offset);
  this->binary_->has_resources_ = (this->binary_->resources_ != nullptr);
}


//
// parse the resources tree
//
ResourceNode* Parser::parse_resource_node(
    const pe_resource_directory_table *directory_table,
    uint32_t base_offset,
    uint32_t current_offset,
    uint32_t depth) {

  const uint32_t numberof_ID_entries   = directory_table->NumberOfIDEntries;
  const uint32_t numberof_name_entries = directory_table->NumberOfNameEntries;

  //const pe_resource_directory_entries* entries_array = reinterpret_cast<const pe_resource_directory_entries*>(directory_table + 1);
  size_t directory_array_offset = current_offset + sizeof(pe_resource_directory_table);

  if (not this->stream_->can_read<pe_resource_directory_entries>(directory_array_offset)) {
    return nullptr;
  }
  pe_resource_directory_entries entries_array = this->stream_->peek<pe_resource_directory_entries>(directory_array_offset);

  std::unique_ptr<ResourceDirectory> directory{new ResourceDirectory{directory_table}};

  directory->depth_ = depth;

  // Iterate over the childs
  for (uint32_t idx = 0; idx < (numberof_name_entries + numberof_ID_entries); ++idx) {

    uint32_t data_rva = entries_array.RVA;
    uint32_t id       = entries_array.NameID.IntegerID;

    directory_array_offset += sizeof(pe_resource_directory_entries);
    if (not this->stream_->can_read<pe_resource_directory_entries>(directory_array_offset)) {
      break;
    }
    entries_array = this->stream_->peek<pe_resource_directory_entries>(directory_array_offset);

    std::u16string name;

    // Get the resource name
    if (id & 0x80000000) {
      uint32_t offset        = id & (~ 0x80000000);
      uint32_t string_offset = base_offset + offset;

      if (this->stream_->can_read<uint16_t>(string_offset)) {
        const uint16_t length = this->stream_->peek<uint16_t>(string_offset);
        if (length <= 100) {
          name = this->stream_->peek_u16string_at(string_offset + sizeof(uint16_t), length);
        }

      }
    }

    if ((0x80000000 & data_rva) == 0) { // We are on a leaf
      uint32_t offset = base_offset + data_rva;

      if (not this->stream_->can_read<pe_resource_data_entry>(offset)) {
        break;
      }

      const pe_resource_data_entry& data_entry = this->stream_->peek<pe_resource_data_entry>(offset);

      uint32_t content_offset = this->binary_->rva_to_offset(data_entry.DataRVA);
      uint32_t content_size   = data_entry.Size;
      uint32_t code_page      = data_entry.Codepage;

      const uint8_t* content_ptr = this->stream_->peek_array<uint8_t>(content_offset, content_size, /* check */false);
      if (content_ptr != nullptr) {

        std::vector<uint8_t> content = {
          content_ptr,
          content_ptr + content_size};

        std::unique_ptr<ResourceData> node{new ResourceData{content, code_page}};

        node->depth_ = depth + 1;
        node->id(id);
        node->name(name);
        node->offset_ = content_offset;

        directory->childs_.push_back(node.release());
      } else {
        LIEF_WARN("The leaf is corrupted");
        break;
      }
    } else { // We are on a directory
      const uint32_t directory_rva = data_rva & (~ 0x80000000);
      const uint32_t offset        = base_offset + directory_rva;
      if (this->stream_->can_read<pe_resource_directory_table>(offset)) {
        const pe_resource_directory_table& nextDirectoryTable = this->stream_->peek<pe_resource_directory_table>(offset);
        if (this->resource_visited_.count(offset) > 0) {
          LIEF_WARN("Infinite loop detected on resources");
          break;
        }
        this->resource_visited_.insert(offset);

        std::unique_ptr<ResourceNode> node{this->parse_resource_node(&nextDirectoryTable, base_offset, offset, depth + 1)};
        if (node) {
          node->id(id);
          node->name(name);
          directory->childs_.push_back(node.release());
        }
      } else { // Corrupted
        LIEF_WARN("The directory is corrupted");
        break;
      }
    }

  }

  return directory.release();
}

//
// parse string table
//
void Parser::parse_string_table(void) {
  LIEF_DEBUG("== Parsing string table ==");
  uint32_t string_table_offset =
    this->binary_->header().pointerto_symbol_table() +
    this->binary_->header().numberof_symbols() * STRUCT_SIZES::Symbol16Size;

  uint32_t size = this->stream_->peek<uint32_t>(string_table_offset);
  if (size < 4) {
    return;
  }
  size -= 4;
  uint32_t current_size = 0;

  while (current_size < size) {
    std::string name = this->stream_->peek_string_at(string_table_offset + sizeof(uint32_t) + current_size);
    current_size += name.size() + 1;
    this->binary_->strings_table_.push_back(name);
  }
}


//
// parse Symbols
//
void Parser::parse_symbols(void) {
  LIEF_DEBUG("== Parsing symbols ==");
  uint32_t symbol_table_offset = this->binary_->header().pointerto_symbol_table();
  uint32_t nb_symbols          = this->binary_->header().numberof_symbols();
  uint32_t current_offset      = symbol_table_offset;

  uint32_t idx = 0;
  while (idx < nb_symbols) {

    if (not this->stream_->can_read<pe_symbol>(current_offset)) {
      break;
    }

    const pe_symbol& raw_symbol = this->stream_->peek<pe_symbol>(current_offset);
    Symbol symbol{&raw_symbol};

    const auto stream_max_size = this->stream_->size();
    if ((raw_symbol.Name.Name.Zeroes & 0xffff) != 0) {
      std::string shortname{raw_symbol.Name.ShortName, sizeof(raw_symbol.Name.ShortName)};
      symbol.name_ = shortname.c_str();
    } else {
      uint64_t offset_name =
        this->binary_->header().pointerto_symbol_table() +
        this->binary_->header().numberof_symbols() * STRUCT_SIZES::Symbol16Size +
        raw_symbol.Name.Name.Offset;
      symbol.name_ = this->stream_->peek_string_at(offset_name, stream_max_size - offset_name);
    }

    if (symbol.section_number() > 0 and
        static_cast<uint32_t>(symbol.section_number()) < this->binary_->sections_.size()) {
      symbol.section_ = this->binary_->sections_[symbol.section_number()];
    }

    for (uint32_t i = 0; i < raw_symbol.NumberOfAuxSymbols; ++i) {
      // Auxiliary Format 1: Function Definitions
      // * Storage class : EXTERNAL
      // * Type          : 0x20 (Function)
      // * Section Number: > 0
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL and
          symbol.type() == 0x20 and symbol.section_number() > 0) {
        LIEF_DEBUG("Format1");
      }


      // Auxiliary Format 2: .bf and .ef Symbols
      // * Storage class : FUNCTION
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_FUNCTION) {
        LIEF_DEBUG("Function");
      }

      // Auxiliary Format 3: Weak Externals
      // * Storage class : EXTERNAL
      // * Section Number: UNDEF
      // * Value         : 0
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL and
          symbol.value() == 0 and static_cast<SYMBOL_SECTION_NUMBER>(symbol.section_number()) == SYMBOL_SECTION_NUMBER::IMAGE_SYM_UNDEFINED) {
        LIEF_DEBUG("Format 3");
      }

      // Auxiliary Format 4: Files
      // * Storage class     : FILE
      // * Name **SHOULD** be: .file
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_FILE) {
        LIEF_DEBUG("Format 4");
        //std::cout << reinterpret_cast<char*>(
      }

      // Auxiliary Format 5: Section Definitions
      // * Storage class     : STATIC
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_STATIC) {
        LIEF_DEBUG("Format 5");
      }

      current_offset += STRUCT_SIZES::Symbol16Size;
    }

    current_offset += STRUCT_SIZES::Symbol16Size;
    idx += 1 + raw_symbol.NumberOfAuxSymbols;
    this->binary_->symbols_.push_back(std::move(symbol));
  }


}


//
// parse Debug
//

void Parser::parse_debug(void) {
  LIEF_DEBUG("== Parsing Debug ==");

  this->binary_->has_debug_ = true;

  uint32_t debugRVA    = this->binary_->data_directory(DATA_DIRECTORY::DEBUG).RVA();
  uint32_t debugoffset = this->binary_->rva_to_offset(debugRVA);
  uint32_t debugsize   = this->binary_->data_directory(DATA_DIRECTORY::DEBUG).size();

  for (size_t i = 0; (i + 1) * sizeof(pe_debug) <= debugsize; i++) {

    const pe_debug& debug_struct = this->stream_->peek<pe_debug>(debugoffset + i * sizeof(pe_debug));
    this->binary_->debug_.push_back(&debug_struct);

    DEBUG_TYPES type = this->binary_->debug().back().type();

    switch (type) {
      case DEBUG_TYPES::IMAGE_DEBUG_TYPE_CODEVIEW:
        {
          this->parse_debug_code_view(this->binary_->debug().back());
          break;
        }

      case DEBUG_TYPES::IMAGE_DEBUG_TYPE_POGO:
        {
          this->parse_debug_pogo(this->binary_->debug().back());
          break;
        }

      case DEBUG_TYPES::IMAGE_DEBUG_TYPE_REPRO:
        {
          this->binary_->is_reproducible_build_ = true;
          break;
        }

      default:
        {}
    }
  }
}

void Parser::parse_debug_code_view(Debug& debug_info) {
  LIEF_DEBUG("Parsing Debug Code View");
  //Debug& debug_info = this->binary_->debug();

  const uint32_t debug_off = debug_info.pointerto_rawdata();
  if (not this->stream_->can_read<uint32_t>(debug_off)) {
    return;
  }

  const CODE_VIEW_SIGNATURES signature = static_cast<CODE_VIEW_SIGNATURES>(this->stream_->peek<uint32_t>(debug_off));

  switch (signature) {
    case CODE_VIEW_SIGNATURES::CVS_PDB_70:
      {

        if (not this->stream_->can_read<pe_pdb_70>(debug_off)) {
          break;
        }
        const pe_pdb_70& pdb_s = this->stream_->peek<pe_pdb_70>(debug_off);

        std::string path = this->stream_->peek_string_at(debug_off + offsetof(pe_pdb_70, filename));

        CodeViewPDB::signature_t sig;
        std::copy(std::begin(pdb_s.signature), std::end(pdb_s.signature), std::begin(sig));
        std::unique_ptr<CodeViewPDB> codeview{new CodeViewPDB{CodeViewPDB::from_pdb70(sig, pdb_s.age, path)}};

        debug_info.code_view_ = codeview.release();
        break;
      }

    default:
      {
        LIEF_WARN("{} is not implemented yet!");
      }
  }


}

void Parser::parse_debug_pogo(Debug& debug_info) {
  LIEF_DEBUG("== Parsing Debug POGO ==");

  const uint32_t debug_size = debug_info.sizeof_data();
  const uint32_t debug_off  = debug_info.pointerto_rawdata();
  if (not this->stream_->can_read<uint32_t>(debug_off)) {
    return;
  }

  const POGO_SIGNATURES signature = static_cast<POGO_SIGNATURES>(this->stream_->peek<uint32_t>(debug_off));

  switch (signature) {
    case POGO_SIGNATURES::POGO_LCTG:
      {
        std::unique_ptr<Pogo> pogo_object {new Pogo};
        pogo_object->signature_ = signature;

        uint32_t offset = sizeof(uint32_t);
        while (offset + sizeof(pe_pogo) < debug_size)
        {
          const pe_pogo& pogo = this->stream_->peek<pe_pogo>(debug_off + offset);
          std::string name = this->stream_->peek_string_at(debug_off + offset + offsetof(pe_pogo, name));

          PogoEntry entry;

          entry.start_rva_ = pogo.start_rva;
          entry.size_      = pogo.size;
          entry.name_      = name;

          pogo_object->entries_.push_back(std::move(entry));

          // pogo entries are 4-bytes aligned
          offset += offsetof(pe_pogo, name) + name.length() + 1;
          offset += ((4 - offset) % 4);
        }

        debug_info.pogo_ = pogo_object.release();
        break;
      }

    default:
      {
        LIEF_WARN("PGO: {} is not implemented yet!", to_string(signature));
      }
  }
}

//
// Parse Export
//
void Parser::parse_exports(void) {
  LIEF_DEBUG("== Parsing exports ==");
  static constexpr uint32_t NB_ENTRIES_LIMIT   = 0x1000000;
  static constexpr size_t MAX_EXPORT_NAME_SIZE = 300;

  uint32_t exports_rva    = this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).RVA();
  uint32_t exports_offset = this->binary_->rva_to_offset(exports_rva);
  uint32_t exports_size   = this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).size();
  std::pair<uint32_t, uint32_t> range = {exports_rva, exports_rva + exports_size};

  if (not this->stream_->can_read<pe_export_directory_table>(exports_offset)) {
    LIEF_WARN("Can't read export table at 0x{:x}", exports_offset);
    return;
  }


  // First Export directory
  const pe_export_directory_table& export_directory_table = this->stream_->peek<pe_export_directory_table>(exports_offset);

  Export export_object = &export_directory_table;
  uint32_t name_offset = this->binary_->rva_to_offset(export_directory_table.NameRVA);
  const std::string name = this->stream_->peek_string_at(name_offset, Parser::MAX_DLL_NAME_SIZE);
  if (Parser::is_valid_dll_name(name)) {
    export_object.name_  = std::move(name);
    LIEF_DEBUG("Export name {}@0x{:x}", export_object.name_, name_offset);
  } else {
    LIEF_INFO("DLL name seems corrupted");
  }

  // Parse Ordinal name table
  uint32_t ordinal_table_offset = this->binary_->rva_to_offset(export_directory_table.OrdinalTableRVA);
  const uint32_t nbof_name_ptr  = export_directory_table.NumberOfNamePointers;
  const uint16_t *ordinal_table = this->stream_->peek_array<uint16_t>(ordinal_table_offset, nbof_name_ptr, /* check */false);

  if (nbof_name_ptr > NB_ENTRIES_LIMIT) {
    LIEF_ERR("Too many name pointer entries: #{:d} (limit: {:d})",
        nbof_name_ptr, NB_ENTRIES_LIMIT);
    return;
  }

  // Parse Ordinal name table
  if (ordinal_table == nullptr) {
    LIEF_ERR("Ordinal table corrupted");
    return;
  }


  // Parse Address table
  uint32_t address_table_offset    = this->binary_->rva_to_offset(export_directory_table.ExportAddressTableRVA);
  const uint32_t nbof_addr_entries = export_directory_table.AddressTableEntries;

  if (nbof_addr_entries > NB_ENTRIES_LIMIT) {
    LIEF_ERR("Too many name address entries: #{:d}", nbof_addr_entries);
    return;
  }

  const uint32_t *address_table = this->stream_->peek_array<uint32_t>(address_table_offset, nbof_addr_entries, /* check */false);

  if (address_table == nullptr) {
    LIEF_ERR("Address table corrupted");
    return;
  }

  if (nbof_addr_entries < nbof_name_ptr) {
    LIEF_ERR("More exported names than addresses");
    return;
  }

  // Parse Export name table
  uint32_t name_table_offset = this->binary_->rva_to_offset(export_directory_table.NamePointerRVA);
  const uint32_t *name_table = this->stream_->peek_array<uint32_t>(name_table_offset, nbof_name_ptr, /* check */false);

  if (name_table == nullptr) {
    LIEF_ERR("Name table corrupted!");
    return;
  }


  // Export address table (EXTERN)
  // =============================
  std::set<size_t> corrupted_entries; // Ordinal value of corrupted entries
  for (size_t i = 0; i < nbof_addr_entries; ++i) {
    const uint32_t value = address_table[i];
    // If value is inside export directory => 'external' function
    if (value >= std::get<0>(range) and value < std::get<1>(range)) {
      uint32_t name_offset = this->binary_->rva_to_offset(value);
      ExportEntry entry;
      entry.name_         = this->stream_->peek_string_at(name_offset);
      entry.address_      = 0;
      entry.is_extern_    = true;
      entry.ordinal_      = i + export_directory_table.OrdinalBase;
      entry.function_rva_ = value;

      export_object.entries_.push_back(std::move(entry));
    } else {
      ExportEntry entry;
      entry.name_         = "";
      entry.address_      = value;
      entry.is_extern_    = false;
      entry.ordinal_      = i + export_directory_table.OrdinalBase;
      entry.function_rva_ = value;


      if (value == 0) {
        corrupted_entries.insert(entry.ordinal_);
      }

      export_object.entries_.push_back(std::move(entry));

    }
  }


  for (size_t i = 0; i < nbof_name_ptr; ++i) {
    if (ordinal_table[i] >= export_object.entries_.size()) {
      LIEF_ERR("Export ordinal is outside the address table");
      break;
    }

    uint32_t name_offset = this->binary_->rva_to_offset(name_table[i]);
    std::string name = this->stream_->peek_string_at(name_offset);

    ExportEntry& entry = export_object.entries_[ordinal_table[i]];

    // Check if the entry is 'extern' and if the export name is already set
    if (entry.is_extern_ and not entry.name_.empty()) {
      std::string fwd_str = entry.name_;

      std::string function = fwd_str;
      std::string library;

      // Split on '.'
      const size_t dot_pos = fwd_str.find('.');
      if (dot_pos != std::string::npos) {
        library  = fwd_str.substr(0, dot_pos);
        function = fwd_str.substr(dot_pos + 1);
      }

      ExportEntry::forward_information_t finfo;
      finfo.library  = library;
      finfo.function = function;

      entry.forward_info_ = finfo;
    }

    entry.name_ = name;

    if (name.size() > MAX_EXPORT_NAME_SIZE) {
      corrupted_entries.insert(entry.ordinal_);
    }
  }

  auto&& it_export = std::begin(export_object.entries_);
  while (it_export != std::end(export_object.entries_)) {
    const ExportEntry& entry = *it_export;
    if (corrupted_entries.count(entry.ordinal()) == 0) {
      ++it_export;
      continue;
    }

    it_export = export_object.entries_.erase(it_export);
  }


  this->binary_->export_ = std::move(export_object);
  this->binary_->has_exports_ = true;

}

void Parser::parse_signature(void) {
  LIEF_DEBUG("== Parsing signature ==");
  static constexpr size_t SIZEOF_HEADER = 8;

  /*** /!\ In this data directory, RVA is used as an **OFFSET** /!\ ****/
  /*********************************************************************/
  const uint32_t signature_offset  = this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).RVA();
  const uint32_t signature_size    = this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).size();
  const uint64_t end_p = signature_offset + signature_size;
  LIEF_DEBUG("Signature Offset: 0x{:04x}", signature_offset);
  LIEF_DEBUG("Signature Size: 0x{:04x}", signature_size);

  this->stream_->setpos(signature_offset);
  while (this->stream_->pos() < end_p) {
    const uint64_t current_p = this->stream_->pos();
    auto length = this->stream_->read<uint32_t>();
    auto revision = this->stream_->read<uint16_t>();
    auto certificate_type = this->stream_->read<uint16_t>();
    LIEF_DEBUG("Signature {}r0x{:x} (0x{:x} bytes)", certificate_type, revision, length);
    const uint8_t* data_ptr = this->stream_->read_array<uint8_t>(length - SIZEOF_HEADER, /* check */false);
    if (data_ptr == nullptr) {
      LIEF_INFO("Can't read 0x{:x} bytes", length);
      break;
    }
    std::vector<uint8_t> raw_signature = {data_ptr, data_ptr + length - SIZEOF_HEADER};
    auto sign = SignatureParser::parse(std::move(raw_signature));

    if (sign) {
      this->binary_->signatures_.push_back(std::move(sign.value()));
    } else {
      LIEF_INFO("Unable to parse the signature");
    }
    this->stream_->align(8);
    if (this->stream_->pos() <= current_p) {
      break;
    }
  }
}


void Parser::parse_overlay(void) {
  LIEF_DEBUG("== Parsing Overlay ==");
  const uint64_t last_section_offset = std::accumulate(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->offset() + section->size(), offset);
      });

  LIEF_DEBUG("Overlay offset: 0x{:x}", last_section_offset);

  if (last_section_offset < this->stream_->size()) {
    const uint64_t overlay_size = this->stream_->size() - last_section_offset;

    LIEF_DEBUG("Overlay size: 0x{:x}", overlay_size);

    const uint8_t* ptr_to_overlay = this->stream_->peek_array<uint8_t>(last_section_offset, overlay_size, /* check */false);
    if (ptr_to_overlay != nullptr) {
      this->binary_->overlay_ = {
          ptr_to_overlay,
          ptr_to_overlay + overlay_size
        };
      this->binary_->overlay_offset_ = last_section_offset;
    }
  } else {
    this->binary_->overlay_ = {};
  }
}

//
// Return the Binary constructed
//
std::unique_ptr<Binary> Parser::parse(const std::string& filename) {
  Parser parser{filename};
  return std::unique_ptr<Binary>{parser.binary_};
}


std::unique_ptr<Binary> Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  return std::unique_ptr<Binary>{parser.binary_};
}

bool Parser::is_valid_import_name(const std::string& name) {

  // According to https://stackoverflow.com/a/23340781
  static constexpr unsigned MAX_IMPORT_NAME_SIZE = 0x1000;

  if (name.empty() or name.size() > MAX_IMPORT_NAME_SIZE) {
    return false;
  }

  if (not is_printable(name)) {
    return false;
  }
  return true;
}


bool Parser::is_valid_dll_name(const std::string& name) {
  //! @brief Minimum size for a DLL's name
  static constexpr unsigned MIN_DLL_NAME_SIZE = 4;

  if (name.size() < MIN_DLL_NAME_SIZE or name.size() > Parser::MAX_DLL_NAME_SIZE) {
    return false;
  }

  if (not is_printable(name)) {
    return false;
  }

  return true;
}

}
}
