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
#include <fstream>
#include <iterator>
#include <iostream>
#include <string>
#include <numeric>

#include <mbedtls/platform.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "logging.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

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

#include "internal_utils.hpp"
#include "signature/pkcs7.h"
#include "Parser.tcc"

// Issue with VS2017
#if defined(IMAGE_FILE_MACHINE_UNKNOWN)
#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#endif

namespace LIEF {
namespace PE {

constexpr size_t Parser::MAX_PADDING_SIZE;
constexpr size_t Parser::MAX_TLS_CALLBACKS;
constexpr size_t Parser::MAX_DLL_NAME_SIZE;
constexpr size_t Parser::MAX_DATA_SIZE;

Parser::~Parser() = default;
Parser::Parser() = default;


Parser::Parser(const std::string& file) :
  LIEF::Parser{file}
{
  if (auto stream = VectorStream::from_file(file)) {
    stream_ = std::make_unique<VectorStream>(std::move(*stream));
  } else {
    LIEF_ERR("Can't create the stream");
  }
}

Parser::Parser(std::vector<uint8_t> data) :
  stream_{std::make_unique<VectorStream>(std::move(data))}
{}


void Parser::init(const std::string& name) {
  stream_->setpos(0);
  auto type = get_type_from_stream(*stream_);
  if (!type) {
    LIEF_ERR("Can't determine PE type.");
    return;
  }
  type_   = type.value();
  binary_ = std::unique_ptr<Binary>(new Binary{});
  binary_->name(name);
  binary_->type_ = type_;

  if (type_ == PE_TYPE::PE32) {
    parse<details::PE32>();
  } else {
    parse<details::PE64>();
  }

}

ok_error_t Parser::parse_dos_stub() {
  const DosHeader& dos_header = binary_->dos_header();

  if (dos_header.addressof_new_exeheader() < sizeof(details::pe_dos_header)) {
    LIEF_ERR("Address of new exe header is corrupted");
    return make_error_code(lief_errors::corrupted);
  }
  const uint64_t sizeof_dos_stub = dos_header.addressof_new_exeheader() - sizeof(details::pe_dos_header);

  LIEF_DEBUG("DOS stub: @0x{:x}:0x{:x}", sizeof(details::pe_dos_header), sizeof_dos_stub);

  const uint64_t dos_stub_offset = sizeof(details::pe_dos_header);
  if (!stream_->peek_data(binary_->dos_stub_, dos_stub_offset, sizeof_dos_stub)) {
    LIEF_ERR("DOS stub corrupted!");
    return make_error_code(lief_errors::read_error);
  }
  return ok();
}


ok_error_t Parser::parse_rich_header() {
  LIEF_DEBUG("Parsing rich header");
  const std::vector<uint8_t>& dos_stub = binary_->dos_stub();
  //SpanStream stream;
  auto res = SpanStream::from_vector(dos_stub);
  if (!res) {
    return make_error_code(lief_errors::parsing_error);
  }
  SpanStream stream = std::move(*res);

  const auto it_rich = std::search(std::begin(dos_stub), std::end(dos_stub),
                                   std::begin(details::Rich_Magic), std::end(details::Rich_Magic));

  if (it_rich == std::end(dos_stub)) {
    LIEF_DEBUG("Rich header not found!");
    return ok();
  }

  const uint64_t end_offset_rich_header = std::distance(std::begin(dos_stub), it_rich);
  LIEF_DEBUG("Offset to rich header: 0x{:x}", end_offset_rich_header);

  if (auto res_xor_key = stream.peek<uint32_t>(end_offset_rich_header + sizeof(details::Rich_Magic))) {
    binary_->rich_header().key(*res_xor_key);
  } else {
    return make_error_code(lief_errors::read_error);
  }

  const uint32_t xor_key = binary_->rich_header().key();
  LIEF_DEBUG("XOR key: 0x{:x}", xor_key);

  int64_t curent_offset = end_offset_rich_header - sizeof(details::Rich_Magic);

  std::vector<uint32_t> values;
  values.reserve(dos_stub.size() / sizeof(uint32_t));

  result<uint32_t> res_count = 0;
  result<uint32_t> res_value = 0;
  uint32_t count = 0;
  uint32_t value;

  while (curent_offset > 0 && stream.pos() < stream.size()) {

    if (auto res_count = stream.peek<uint32_t>(curent_offset)) {
      count = *res_count ^ xor_key;
    } else {
      break;
    }

    curent_offset -= sizeof(uint32_t);
    if (auto res_value = stream.peek<uint32_t>(curent_offset)) {
      value = *res_value ^ xor_key;
    } else {
      break;
    }

    curent_offset -= sizeof(uint32_t);

    if (value == 0 && count == 0) { // Skip padding entry
      continue;
    }

    if (value == details::DanS_Magic_number ||
        count == details::DanS_Magic_number)
    {
      break;
    }

    uint16_t build_number = value & 0xFFFF;
    uint16_t id           = (value >> 16) & 0xFFFF;

    LIEF_DEBUG("ID:           0x{:04x}", id);
    LIEF_DEBUG("Build Number: 0x{:04x}", build_number);
    LIEF_DEBUG("Count:        0x{:d}", count);

    binary_->rich_header().add_entry(id, build_number, count);
  }

  binary_->has_rich_header_ = true;
  return ok();
}

ok_error_t Parser::parse_sections() {
  static constexpr size_t NB_MAX_SECTIONS = 1000;
  LIEF_DEBUG("Parsing sections");


  const uint32_t pe_header_off   = binary_->dos_header().addressof_new_exeheader();
  const uint32_t opt_header_off  = pe_header_off + sizeof(details::pe_header);
  const uint32_t sections_offset = opt_header_off + binary_->header().sizeof_optional_header();

  uint32_t first_section_offset = UINT_MAX;

  uint32_t numberof_sections = binary_->header().numberof_sections();
  if (numberof_sections > NB_MAX_SECTIONS) {
    LIEF_ERR("The PE binary has {} sections while the LIEF limit is {}.\n"
             "Only the first {} will be parsed", numberof_sections, NB_MAX_SECTIONS, NB_MAX_SECTIONS);
    numberof_sections = NB_MAX_SECTIONS;
  }

  stream_->setpos(sections_offset);
  for (size_t i = 0; i < numberof_sections; ++i) {
    details::pe_section raw_sec;
    if (auto res = stream_->read<details::pe_section>()) {
      raw_sec = *res;
    } else {
      LIEF_ERR("Can't read section at 0x{:x}", stream_->pos());
      break;
    }
    auto section = std::make_unique<Section>(raw_sec);
    uint32_t size_to_read = 0;
    uint32_t offset = raw_sec.PointerToRawData;
    if (offset > 0) {
      first_section_offset = std::min(first_section_offset, offset);
    }

    size_to_read = raw_sec.VirtualSize > 0 ?
                   std::min(raw_sec.VirtualSize, raw_sec.SizeOfRawData) : // According to Corkami
                   raw_sec.SizeOfRawData;

    if ((offset + size_to_read) > stream_->size()) {
      uint32_t delta = (offset + size_to_read) - stream_->size();
      size_to_read = size_to_read - delta;
    }

    if (size_to_read > Parser::MAX_DATA_SIZE) {
      LIEF_WARN("Data of section section '{}' is too large (0x{:x})", section->name(), size_to_read);
    } else {

      if (!stream_->peek_data(section->content_, offset, size_to_read)) {
        LIEF_ERR("Section #{:d} ({}) is corrupted", i, section->name());
      }

      const uint64_t padding_size = section->size() - size_to_read;

      // Treat content between two sections (that is not wrapped in a section) as 'padding'
      uint64_t hole_size = 0;
      if (i < numberof_sections - 1) {
        // As we *read* at the beginning of the loop, the cursor is already on the next one
        auto res_next_section = stream_->peek<details::pe_section>();
        if (!res_next_section) {
          LIEF_ERR("Can't read the {} + 1 section", i + 1);
        } else {
          const details::pe_section& next_section = *res_next_section;
          const uint64_t sec_offset = next_section.PointerToRawData;
          if (offset + size_to_read + padding_size < sec_offset) {
            hole_size = sec_offset - (offset + size_to_read + padding_size);
          }
        }
      }
      uint64_t padding_to_read = padding_size + hole_size;
      if (padding_to_read > Parser::MAX_PADDING_SIZE) {
        LIEF_WARN("The padding size of section '{}' is huge. Only the first {} bytes will be taken"
                  " into account", section->name(), Parser::MAX_PADDING_SIZE);
        padding_to_read = Parser::MAX_PADDING_SIZE;
      }

      if (!stream_->peek_data(section->padding_, offset + size_to_read, padding_to_read)) {
        LIEF_ERR("Can't read the padding content of section '{}'", section->name());
      }
    }
    binary_->sections_.push_back(std::move(section));
  }

  const uint32_t last_section_header_offset = sections_offset + numberof_sections * sizeof(details::pe_section);
  const size_t padding_size = first_section_offset - last_section_header_offset;
  if (!stream_->peek_data(binary_->section_offset_padding_, last_section_header_offset, padding_size)) {
    LIEF_ERR("Can't read the padding");
  }
  binary_->available_sections_space_ = (first_section_offset - last_section_header_offset) / sizeof(details::pe_section) - 1;
  LIEF_DEBUG("Number of sections that could be added: #{:d}", binary_->available_sections_space_);
  return ok();
}


//
// parse relocations
//
ok_error_t Parser::parse_relocations() {
  static constexpr size_t MAX_RELOCATION_ENTRIES = 100000;
  LIEF_DEBUG("== Parsing relocations ==");

  const uint32_t offset = binary_->rva_to_offset(
      binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA());

  const uint32_t max_size = binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size();
  const uint32_t max_offset = offset + max_size;

  auto res_relocation_headers = stream_->peek<details::pe_base_relocation_block>(offset);
  if (!res_relocation_headers) {
    return make_error_code(lief_errors::read_error);
  }

  uint32_t current_offset = offset;
  while (res_relocation_headers && current_offset < max_offset && res_relocation_headers->PageRVA != 0) {
    const details::pe_base_relocation_block& raw_struct = *res_relocation_headers;
    auto relocation = std::make_unique<Relocation>(raw_struct);

    if (raw_struct.BlockSize < sizeof(details::pe_base_relocation_block)) {
      LIEF_ERR("Relocation corrupted: BlockSize is too small");
      break;
    }

    if (raw_struct.BlockSize > binary_->optional_header().sizeof_image()) {
      LIEF_ERR("Relocation corrupted: BlockSize is out of bound the binary's virtual size");
      break;
    }

    size_t numberof_entries = (raw_struct.BlockSize - sizeof(details::pe_base_relocation_block)) / sizeof(uint16_t);
    if (numberof_entries > MAX_RELOCATION_ENTRIES) {
      LIEF_WARN("The number of relocation entries () is larger than the LIEF's limit ({})\n"
                "Only the first {} will be parsed", numberof_entries,
                MAX_RELOCATION_ENTRIES, MAX_RELOCATION_ENTRIES);
      numberof_entries = MAX_RELOCATION_ENTRIES;
    }


    stream_->setpos(current_offset + sizeof(details::pe_base_relocation_block));
    for (size_t i = 0; i < numberof_entries; ++i) {
      auto res_entry = stream_->read<uint16_t>();
      if (!res_entry) {
        LIEF_ERR("Can't parse relocation entry #{}", i);
        break;
      }
      auto entry = std::make_unique<RelocationEntry>(*res_entry);
      entry->relocation_ = relocation.get();
      relocation->entries_.push_back(std::move(entry));
    }

    binary_->relocations_.push_back(std::move(relocation));
    current_offset += raw_struct.BlockSize;
    res_relocation_headers = stream_->peek<details::pe_base_relocation_block>(current_offset);
  }

  binary_->has_relocations_ = true;
  return ok();
}


//
// parse ressources
//
ok_error_t Parser::parse_resources() {
  LIEF_DEBUG("== Parsing resources ==");

  const uint32_t resources_rva = binary_->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA();
  LIEF_DEBUG("Resources RVA: 0x{:04x}", resources_rva);

  const uint32_t offset = binary_->rva_to_offset(resources_rva);
  LIEF_DEBUG("Resources Offset: 0x{:04x}", offset);

  const auto res_directory_table = stream_->peek<details::pe_resource_directory_table>(offset);
  if (!res_directory_table) {
    return make_error_code(lief_errors::read_error);
  }

  binary_->resources_     = parse_resource_node(*res_directory_table, offset, offset);
  binary_->has_resources_ = binary_->resources_ != nullptr;
  return ok();
}


//
// parse the resources tree
//
std::unique_ptr<ResourceNode> Parser::parse_resource_node(const details::pe_resource_directory_table& directory_table,
                                          uint32_t base_offset, uint32_t current_offset, uint32_t depth) {

  const uint32_t numberof_ID_entries   = directory_table.NumberOfIDEntries;
  const uint32_t numberof_name_entries = directory_table.NumberOfNameEntries;

  //const pe_resource_directory_entries* entries_array = reinterpret_cast<const pe_resource_directory_entries*>(directory_table + 1);
  size_t directory_array_offset = current_offset + sizeof(details::pe_resource_directory_table);
  details::pe_resource_directory_entries entries_array;

  if (auto res_entries_array = stream_->peek<details::pe_resource_directory_entries>(directory_array_offset)) {
    entries_array = *res_entries_array;
  } else {
    return nullptr;
  }

  auto directory = std::make_unique<ResourceDirectory>(directory_table);
  directory->depth_ = depth;

  // Iterate over the childs
  for (size_t idx = 0; idx < (numberof_name_entries + numberof_ID_entries); ++idx) {

    uint32_t data_rva = entries_array.RVA;
    uint32_t id       = entries_array.NameID.IntegerID;

    directory_array_offset += sizeof(details::pe_resource_directory_entries);
    if (auto res_entries_array = stream_->peek<details::pe_resource_directory_entries>(directory_array_offset)) {
      entries_array = *res_entries_array;
    } else {
      break;
    }

    result<std::u16string> name;

    // Get the resource name
    if ((id & 0x80000000) != 0u) {
      uint32_t offset        = id & (~ 0x80000000);
      uint32_t string_offset = base_offset + offset;

      auto res_length = stream_->peek<uint16_t>(string_offset);
      if (res_length && *res_length <= 100) {
        name = stream_->peek_u16string_at(string_offset + sizeof(uint16_t), *res_length);
        if (!name) {
          LIEF_ERR("Node's name for the node id: {} is corrupted", id);
        }
      }
    }

    if ((0x80000000 & data_rva) == 0) { // We are on a leaf
      uint32_t offset = base_offset + data_rva;
      details::pe_resource_data_entry data_entry;

      if (auto res_data_entry = stream_->peek<details::pe_resource_data_entry>(offset)) {
        data_entry = *res_data_entry;
      } else {
        break;
      }

      uint32_t content_offset = binary_->rva_to_offset(data_entry.DataRVA);
      uint32_t content_size   = data_entry.Size;
      uint32_t code_page      = data_entry.Codepage;

      std::vector<uint8_t> leaf_data;
      if (stream_->peek_data(leaf_data, content_offset, content_size)) {
        auto node = std::make_unique<ResourceData>(std::move(leaf_data), code_page);

        node->depth_ = depth + 1;
        node->id(id);
        node->offset_ = content_offset;
        if (name) {
          node->name(*name);
        }

        directory->childs_.push_back(std::move(node));
      } else {
        LIEF_DEBUG("The leaf of the node id {} is corrupted", id);
        break;
      }
    } else { // We are on a directory
      const uint32_t directory_rva = data_rva & (~ 0x80000000);
      const uint32_t offset        = base_offset + directory_rva;
      if (!resource_visited_.insert(offset).second) {
        LIEF_WARN("Infinite loop detected on resources");
        break;
      }

      if (auto res_next_dir_table = stream_->peek<details::pe_resource_directory_table>(offset)) {
        if (auto node = parse_resource_node(*res_next_dir_table, base_offset, offset, depth + 1)) {
          if (name) {
            node->name(*name);
          }
          node->id(id);
          directory->childs_.push_back(std::move(node));
        } else {
          // node is a nullptr
          continue;
        }
      } else {
        LIEF_WARN("The directory of the node id {} is corrupted", id);
        break;
      }
    }
  }
  return directory;
}

//
// parse string table
//
ok_error_t Parser::parse_string_table() {
  LIEF_DEBUG("== Parsing string table ==");
  uint32_t string_table_offset =
    binary_->header().pointerto_symbol_table() +
    binary_->header().numberof_symbols() * details::STRUCT_SIZES::Symbol16Size;

  auto res_size = stream_->peek<uint32_t>(string_table_offset);
  if (!res_size) {
    return res_size.error();
  }

  auto size = *res_size;
  if (size < 4) {
    return ok();
  }
  size -= 4;
  uint32_t current_size = 0;

  while (current_size < size) {
    auto res_name = stream_->peek_string_at(string_table_offset + sizeof(uint32_t) + current_size);
    if (!res_name) {
      break;
    }
    std::string name = *res_name;
    current_size += name.size() + 1;
    binary_->strings_table_.push_back(name);
  }
  return ok();
}


//
// parse Symbols
//
ok_error_t Parser::parse_symbols() {
  LIEF_DEBUG("== Parsing symbols ==");
  uint32_t symbol_table_offset = binary_->header().pointerto_symbol_table();
  uint32_t nb_symbols          = binary_->header().numberof_symbols();
  uint32_t current_offset      = symbol_table_offset;

  uint32_t idx = 0;
  while (idx < nb_symbols) {


    auto res_raw_symbol = stream_->peek<details::pe_symbol>(current_offset);
    if (!res_raw_symbol) {
      break;
    }
    auto raw_symbol = *res_raw_symbol;
    Symbol symbol = raw_symbol;

    const auto stream_max_size = stream_->size();
    if ((raw_symbol.Name.Name.Zeroes & 0xffff) != 0) {
      std::string shortname{raw_symbol.Name.ShortName, sizeof(raw_symbol.Name.ShortName)};
      symbol.name_ = shortname.c_str();
    } else {
      uint64_t offset_name =
        binary_->header().pointerto_symbol_table() +
        binary_->header().numberof_symbols() * details::STRUCT_SIZES::Symbol16Size +
        raw_symbol.Name.Name.Offset;
      auto res_string = stream_->peek_string_at(offset_name, stream_max_size - offset_name);
      if (res_string) {
        symbol.name_ = std::move(*res_string);
      }
    }

    if (symbol.section_number() > 0 &&
        static_cast<uint32_t>(symbol.section_number()) < binary_->sections_.size()) {
      symbol.section_ = binary_->sections_[symbol.section_number()].get();
    }

    for (uint32_t i = 0; i < raw_symbol.NumberOfAuxSymbols; ++i) {
      // Auxiliary Format 1: Function Definitions
      // * Storage class : EXTERNAL
      // * Type          : 0x20 (Function)
      // * Section Number: > 0
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL &&
          symbol.type() == 0x20 && symbol.section_number() > 0) {
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
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL &&
          symbol.value() == 0 && static_cast<SYMBOL_SECTION_NUMBER>(symbol.section_number()) == SYMBOL_SECTION_NUMBER::IMAGE_SYM_UNDEFINED) {
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

      current_offset += details::STRUCT_SIZES::Symbol16Size;
    }

    current_offset += details::STRUCT_SIZES::Symbol16Size;
    idx += 1 + raw_symbol.NumberOfAuxSymbols;
    binary_->symbols_.push_back(std::move(symbol));
  }

  return ok();
}


//
// parse Debug
//

ok_error_t Parser::parse_debug() {
  LIEF_DEBUG("== Parsing Debug ==");

  binary_->has_debug_ = true;

  uint32_t debug_rva    = binary_->data_directory(DATA_DIRECTORY::DEBUG).RVA();
  uint32_t debug_offset = binary_->rva_to_offset(debug_rva);
  uint32_t debug_size   = binary_->data_directory(DATA_DIRECTORY::DEBUG).size();

  for (size_t i = 0; (i + 1) * sizeof(details::pe_debug) <= debug_size; i++) {
    auto res_debug_struct = stream_->peek<details::pe_debug>(debug_offset + i * sizeof(details::pe_debug));
    if (!res_debug_struct) {
      break;
    }
    binary_->debug_.push_back(*res_debug_struct);

    DEBUG_TYPES type = binary_->debug().back().type();

    switch (type) {
      case DEBUG_TYPES::IMAGE_DEBUG_TYPE_CODEVIEW:
        {
          parse_debug_code_view(binary_->debug().back());
          break;
        }

      case DEBUG_TYPES::IMAGE_DEBUG_TYPE_POGO:
        {
          parse_debug_pogo(binary_->debug().back());
          break;
        }

      case DEBUG_TYPES::IMAGE_DEBUG_TYPE_REPRO:
        {
          binary_->is_reproducible_build_ = true;
          break;
        }

      default:
        {}
    }
  }
  return ok();
}

ok_error_t Parser::parse_debug_code_view(Debug& debug_info) {
  LIEF_DEBUG("Parsing Debug Code View");

  const uint32_t debug_off = debug_info.pointerto_rawdata();
  auto res_sig = stream_->peek<uint32_t>(debug_off);
  if (!res_sig) {
    return res_sig.error();
  }

  const auto signature = static_cast<CODE_VIEW_SIGNATURES>(*res_sig);

  switch (signature) {
    case CODE_VIEW_SIGNATURES::CVS_PDB_70:
      {
        const auto pdb_s = stream_->peek<details::pe_pdb_70>(debug_off);
        if (!pdb_s) {
          break;
        }

        CodeViewPDB::signature_t sig;
        std::move(std::begin(pdb_s->signature), std::end(pdb_s->signature), std::begin(sig));

        auto res_path = stream_->peek_string_at(debug_off + offsetof(details::pe_pdb_70, filename));
        if (res_path) {
          auto codeview = std::make_unique<CodeViewPDB>(CodeViewPDB::from_pdb70(sig, pdb_s->age, *res_path));
          debug_info.code_view_ = std::move(codeview);
        }
        break;
      }

    default:
      {
        LIEF_INFO("Signature {} is not implemented yet!", to_string(signature));
      }
  }
  return ok();
}

ok_error_t Parser::parse_debug_pogo(Debug& debug_info) {
  LIEF_DEBUG("== Parsing Debug POGO ==");

  const uint32_t debug_size = debug_info.sizeof_data();
  const uint32_t debug_off  = debug_info.pointerto_rawdata();

  auto res_sig = stream_->peek<uint32_t>(debug_off);
  if (!res_sig) {
    return res_sig.error();
  }
  const auto signature = static_cast<POGO_SIGNATURES>(*res_sig);

  switch (signature) {
    case POGO_SIGNATURES::POGO_LCTG:
      {
        auto pogo_object = std::make_unique<Pogo>();
        pogo_object->signature_ = signature;

        uint32_t offset = sizeof(uint32_t);
        while (offset + sizeof(details::pe_pogo) < debug_size) {
          auto res_pogo = stream_->peek<details::pe_pogo>(debug_off + offset);
          auto res_name = stream_->peek_string_at(debug_off + offset + offsetof(details::pe_pogo, name));
          if (!res_pogo || !res_name) {
            break;
          }

          PogoEntry entry;

          entry.start_rva_ = res_pogo->start_rva;
          entry.size_      = res_pogo->size;
          entry.name_      = std::move(*res_name);

          // pogo entries are 4-bytes aligned
          offset += offsetof(details::pe_pogo, name) + entry.name_.length() + 1;
          offset += ((4 - offset) % 4);

          pogo_object->entries_.push_back(std::move(entry));
        }

        debug_info.pogo_ = std::move(pogo_object);
        break;
      }

    default:
      {
        LIEF_INFO("PGO with signature 0x{:x} is not implemented yet!", *res_sig);
      }
  }
  return ok();
}


inline result<uint32_t> address_table_value(BinaryStream& stream,
                                            uint32_t address_table_offset, size_t i) {
  using element_t = uint32_t;
  const size_t element_offset = address_table_offset + i * sizeof(element_t);
  if (auto res = stream.peek<element_t>(element_offset)) {
    return *res;
  }
  return make_error_code(lief_errors::read_error);
}

inline result<uint16_t> ordinal_table_value(BinaryStream& stream,
                                            uint32_t ordinal_table_offset, size_t i) {
  using element_t = uint16_t;

  const size_t element_offset = ordinal_table_offset + i * sizeof(element_t);
  if (auto res = stream.peek<element_t>(element_offset)) {
    return *res;
  }
  return make_error_code(lief_errors::read_error);
}

inline result<uint32_t> name_table_value(BinaryStream& stream,
                                         uint32_t name_table_offset, size_t i) {
  using element_t = uint32_t;

  const size_t element_offset = name_table_offset + i * sizeof(element_t);
  if (auto res = stream.peek<element_t>(element_offset)) {
    return *res;
  }
  return make_error_code(lief_errors::read_error);
}


//
// Parse Export
//
ok_error_t Parser::parse_exports() {
  LIEF_DEBUG("== Parsing exports ==");
  static constexpr uint32_t NB_ENTRIES_LIMIT   = 0x1000000;
  static constexpr size_t MAX_EXPORT_NAME_SIZE = 3000; // Because of C++ mangling

  struct range_t {
    uint32_t start;
    uint32_t end;
  };
  const DataDirectory& export_dir = binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE);

  uint32_t exports_rva    = export_dir.RVA();
  uint32_t exports_size   = export_dir.size();
  uint32_t exports_offset = binary_->rva_to_offset(exports_rva);
  range_t range = {exports_rva, exports_rva + exports_size};

  // First Export directory
  details::pe_export_directory_table export_dir_tbl;
  if (auto res = stream_->peek<details::pe_export_directory_table>(exports_offset)) {
    export_dir_tbl = *res;
  } else {
    LIEF_WARN("Can't read the export table at 0x{:x}", exports_offset);
    return make_error_code(lief_errors::read_error);
  }

  Export export_object = export_dir_tbl;
  uint32_t name_offset = binary_->rva_to_offset(export_dir_tbl.NameRVA);
  if (auto res_name = stream_->peek_string_at(name_offset, Parser::MAX_DLL_NAME_SIZE)) {
    std::string name = *res_name;
    if (Parser::is_valid_dll_name(name)) {
      export_object.name_ = std::move(name);
      LIEF_DEBUG("Export name {}@0x{:x}", export_object.name_, name_offset);
    } else {
      // Empty export names are not allowed
      if (name.empty()) {
        return make_error_code(lief_errors::corrupted);
      }
      LIEF_DEBUG("'{}' is not a valid export name", printable_string(name));
    }
  } else {
    LIEF_INFO("DLL name seems corrupted");
  }
  const uint32_t nbof_addr_entries = export_dir_tbl.AddressTableEntries;
  const uint32_t nbof_name_ptr     = export_dir_tbl.NumberOfNamePointers;

  const uint16_t ordinal_base = export_dir_tbl.OrdinalBase;

  const uint32_t address_table_offset = binary_->rva_to_offset(export_dir_tbl.ExportAddressTableRVA);
  const uint32_t ordinal_table_offset = binary_->rva_to_offset(export_dir_tbl.OrdinalTableRVA);
  const uint32_t name_table_offset    = binary_->rva_to_offset(export_dir_tbl.NamePointerRVA);

  LIEF_DEBUG("Number of entries:   {}", nbof_addr_entries);
  LIEF_DEBUG("Number of names ptr: {}", nbof_name_ptr);
  LIEF_DEBUG("Ordinal Base:        {}", ordinal_base);
  LIEF_DEBUG("External Range:      0x{:06x} - 0x{:06x}", range.start, range.end);

  if (nbof_addr_entries > NB_ENTRIES_LIMIT) {
    LIEF_WARN("Export.AddressTableEntries is too large ({})", nbof_addr_entries);
    return make_error_code(lief_errors::corrupted);
  }

  if (nbof_name_ptr > NB_ENTRIES_LIMIT) {
    LIEF_WARN("Export.NumberOfNamePointers is too large ({})", nbof_name_ptr);
    return make_error_code(lief_errors::corrupted);
  }

  Export::entries_t export_entries;
  export_entries.reserve(nbof_addr_entries);

  std::set<uint32_t> corrupted_entries; // Ordinal value of corrupted entries
  /*
   * First, process the Export address table.
   * This table is an array of RVAs
   */
  for (size_t i = 0; i < nbof_addr_entries; ++i) {
    uint32_t addr_value = 0;
    if (auto res = address_table_value(*stream_, address_table_offset, i)) {
      addr_value = *res;
    } else {
      LIEF_WARN("Can't read the Export.address_table[{}]", i);
      break;
    }
    LIEF_DEBUG("Export.address_table[{}].addr_value: 0x{:04x}", i, addr_value);
    const uint16_t ordinal = i + ordinal_base;
    const bool is_extern   = range.start <= addr_value && addr_value < range.end;
    const uint32_t address = is_extern ? 0 : addr_value;

    ExportEntry entry{address, is_extern, ordinal, addr_value};
    if (addr_value == 0) {
      corrupted_entries.insert(ordinal);
    }

    if (is_extern && addr_value > 0) {
      uint32_t name_offset = binary_->rva_to_offset(addr_value);
      if (auto res = stream_->peek_string_at(name_offset)) {
        entry.name_ = std::move(*res);
        if (entry.name_.size() > MAX_EXPORT_NAME_SIZE || !is_printable(entry.name_)) {
          LIEF_INFO("'{}' is not a valid export name", printable_string(entry.name_));
          entry = ExportEntry{address, is_extern, ordinal, addr_value};
          entry.name_.clear();
        }
      }
    }
    export_entries.push_back(std::move(entry));
  }

  for (size_t i = 0; i < nbof_name_ptr; ++i) {
    uint16_t ordinal = 0;

    if (auto res = ordinal_table_value(*stream_, ordinal_table_offset, i)) {
      ordinal = *res;
    } else {
      LIEF_WARN("Can't read the Export.ordinal_table[{}]", i);
      break;
    }

    if (ordinal >= export_entries.size()) {
      LIEF_WARN("Ordinal value ordinal_table[{}]: {} is out of range the export entries", i, ordinal);
      break;
    }

    ExportEntry& entry = export_entries[ordinal];

    if (entry.name_.empty()) {
      uint32_t name_offset = 0;
      if (auto res = name_table_value(*stream_, name_table_offset, i)) {
        name_offset = binary_->rva_to_offset(*res);
      } else {
        LIEF_WARN("Can't read the Export.name_table[{}]", i);
        corrupted_entries.insert(entry.ordinal_);
        continue;
      }
      if (auto res = stream_->peek_string_at(name_offset)) {
        std::string name = *res;
        if (name.empty() || name.size() > MAX_EXPORT_NAME_SIZE) {
          if (!name.empty()) {
            LIEF_WARN("'{}' is not a valid export name", printable_string(name));
          }
          corrupted_entries.insert(entry.ordinal_);
        } else {
          entry.name_ = std::move(name);
        }
      } else {
        LIEF_WARN("Can't read the Export.enries[{}].name at 0x{:x}", i, name_offset);
        corrupted_entries.insert(entry.ordinal_);
      }
    }

    if (entry.is_extern_ && !entry.name_.empty()) {
      std::string fwd_str = entry.name_;
      std::string function = fwd_str;
      std::string library;

      // Split on '.'
      const size_t dot_pos = fwd_str.find('.');
      if (dot_pos != std::string::npos) {
        library  = fwd_str.substr(0, dot_pos);
        function = fwd_str.substr(dot_pos + 1);
      }
      entry.set_forward_info(std::move(library), std::move(function));
    }
  }

  for (ExportEntry& entry : export_entries) {
    if (corrupted_entries.count(entry.ordinal()) == 0) {
      export_object.entries_.push_back(std::move(entry));
    }
  }

  binary_->export_ = std::move(export_object);
  binary_->has_exports_ = true;
  return ok();
}

ok_error_t Parser::parse_signature() {
  LIEF_DEBUG("== Parsing signature ==");
  static constexpr size_t SIZEOF_HEADER = 8;

  /*** /!\ In this data directory, RVA is used as an **OFFSET** /!\ ****/
  /*********************************************************************/
  const uint32_t signature_offset  = binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).RVA();
  const uint32_t signature_size    = binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).size();
  const uint64_t end_p = signature_offset + signature_size;
  LIEF_DEBUG("Signature Offset: 0x{:04x}", signature_offset);
  LIEF_DEBUG("Signature Size:   0x{:04x}", signature_size);

  stream_->setpos(signature_offset);
  while (stream_->pos() < end_p) {
    const uint64_t current_p = stream_->pos();

    uint32_t length = 0;
    uint16_t revision = 0;
    uint16_t certificate_type = 0;

    if (auto res = stream_->read<uint32_t>()) {
      length = *res;
    } else {
      return res.error();
    }

    if (length <= SIZEOF_HEADER) {
      LIEF_WARN("The signature seems corrupted!");
      break;
    }

    if (auto res = stream_->read<uint16_t>()) {
      revision = *res;
    } else {
      LIEF_ERR("Can't parse signature revision");
      break;
    }

    if (auto res = stream_->read<uint16_t>()) {
      certificate_type = *res;
    } else {
      LIEF_ERR("Can't read certificate_type");
      break;
    }

    LIEF_DEBUG("Signature {}r0x{:x} (0x{:x} bytes)", certificate_type, revision, length);

    std::vector<uint8_t> raw_signature;
    if (!stream_->read_data(raw_signature, length - SIZEOF_HEADER)) {
      LIEF_INFO("Can't read 0x{:x} bytes", length);
      break;
    }

    if (auto sign = SignatureParser::parse(std::move(raw_signature))) {
      binary_->signatures_.push_back(std::move(*sign));
    } else {
      LIEF_INFO("Unable to parse the signature");
    }
    stream_->align(8);
    if (stream_->pos() <= current_p) {
      break;
    }
  }
  return ok();
}


ok_error_t Parser::parse_overlay() {
  LIEF_DEBUG("== Parsing Overlay ==");
  const uint64_t last_section_offset = std::accumulate(
      std::begin(binary_->sections_), std::end(binary_->sections_), uint64_t{ 0u },
      [] (uint64_t offset, const std::unique_ptr<Section>& section) {
        return std::max<uint64_t>(section->offset() + section->size(), offset);
      });

  LIEF_DEBUG("Overlay offset: 0x{:x}", last_section_offset);

  if (last_section_offset < stream_->size()) {
    const uint64_t overlay_size = stream_->size() - last_section_offset;

    LIEF_DEBUG("Overlay size: 0x{:x}", overlay_size);
    if (stream_->peek_data(binary_->overlay_, last_section_offset, overlay_size)) {
      binary_->overlay_offset_ = last_section_offset;
    }
  }
  return ok();
}


result<uint32_t> Parser::checksum() {
  /*
   * (re)compute the checksum specified in OptionalHeader::CheckSum
   */
  ScopedStream chk_stream(*stream_, 0);
  const uint32_t padding = stream_->size() % sizeof(uint16_t);

  LIEF_DEBUG("padding: {}", padding);

  uint32_t partial_sum = 0;
  const uint64_t file_length = stream_->size();
  uint64_t nb_chunk = (file_length + 1) >> 1; // Number of uint16_t chunks

  while (*stream_) {
    uint16_t chunk = 0;
    if (auto res = stream_->read<uint16_t>()) {
      chunk = *res;
    } else {
      break;
    }
    --nb_chunk;
    partial_sum += chunk;
    partial_sum = (partial_sum >> 16) + (partial_sum & 0xffff);
  }

  if (nb_chunk > 0) {
    if (auto res = stream_->read<uint8_t>()) {
      partial_sum += *res;
      partial_sum = (partial_sum >> 16) + (partial_sum & 0xffff);
    }
  }

  auto partial_sum_res = static_cast<uint16_t>(((partial_sum >> 16) + partial_sum) & 0xffff);
  uint32_t binary_checksum = binary_->optional_header().checksum();
  uint32_t adjust_sum_lsb = binary_checksum & 0xFFFF;
  uint32_t adjust_sum_msb = binary_checksum >> 16;

  partial_sum_res -= (partial_sum_res < adjust_sum_lsb);
  partial_sum_res -= adjust_sum_lsb;

  partial_sum_res -= (partial_sum_res < adjust_sum_msb);
  partial_sum_res -= adjust_sum_msb;

  return static_cast<uint32_t>(partial_sum_res) + file_length;
}

//
// Return the Binary constructed
//
std::unique_ptr<Binary> Parser::parse(const std::string& filename) {
  if (!is_pe(filename)) {
    return nullptr;
  }
  Parser parser{filename};
  parser.init(filename);
  return std::move(parser.binary_);
}


std::unique_ptr<Binary> Parser::parse(std::vector<uint8_t> data, const std::string& name) {
  if (!is_pe(data)) {
    return nullptr;
  }
  Parser parser{std::move(data)};
  parser.init(name);
  return std::move(parser.binary_);
}

bool Parser::is_valid_import_name(const std::string& name) {

  // According to https://stackoverflow.com/a/23340781
  static constexpr unsigned MAX_IMPORT_NAME_SIZE = 0x1000;

  if (name.empty() || name.size() > MAX_IMPORT_NAME_SIZE) {
    return false;
  }
  const bool valid_chars = std::all_of(std::begin(name), std::end(name),
      [] (char c) {
        return ::isprint(c);
      });
  return valid_chars;
}


bool Parser::is_valid_dll_name(const std::string& name) {
  //! @brief Minimum size for a DLL's name
  static constexpr unsigned MIN_DLL_NAME_SIZE = 4;

  if (name.size() < MIN_DLL_NAME_SIZE || name.size() > Parser::MAX_DLL_NAME_SIZE) {
    return false;
  }

  if (!is_printable(name)) {
    return false;
  }

  return true;
}

}
}
