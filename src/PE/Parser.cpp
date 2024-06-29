/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <iterator>
#include <string>
#include <numeric>
#include "logging.hpp"


#include "LIEF/BinaryStream/SpanStream.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/ExportEntry.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/debug/CodeViewPDB.hpp"
#include "LIEF/PE/debug/Pogo.hpp"
#include "LIEF/PE/debug/Repro.hpp"
#include "LIEF/PE/debug/PogoEntry.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/RichHeader.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/utils.hpp"

#include "internal_utils.hpp"
#include "Parser.tcc"

// Issue with VS2017
#if defined(IMAGE_FILE_MACHINE_UNKNOWN)
#define LIEF_PE_FORCE_UNDEF
#include "LIEF/PE/undef.h"
#endif

namespace LIEF {
namespace PE {

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
  Parser{std::make_unique<VectorStream>(std::move(data))}
{}

Parser::Parser(std::unique_ptr<BinaryStream> stream) :
  stream_{std::move(stream)}
{}

void Parser::init(const ParserConfig& config) {
  stream_->setpos(0);
  auto type = get_type_from_stream(*stream_);
  if (!type) {
    LIEF_ERR("Can't determine PE type.");
    return;
  }

  type_   = type.value();
  binary_ = std::unique_ptr<Binary>(new Binary{});
  binary_->type_ = type_;
  binary_->original_size_ = stream_->size();
  config_ = config;

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
  span<const uint8_t> dos_stub = binary_->dos_stub();

  const SpanStream stream(dos_stub);

  const auto* it_rich = std::search(std::begin(dos_stub), std::end(dos_stub),
                                    std::begin(details::Rich_Magic), std::end(details::Rich_Magic));

  if (it_rich == std::end(dos_stub)) {
    LIEF_DEBUG("Rich header not found!");
    return ok();
  }
  auto rich_header = std::make_unique<RichHeader>();

  const uint64_t end_offset_rich_header = std::distance(std::begin(dos_stub), it_rich);
  LIEF_DEBUG("Offset to rich header: 0x{:x}", end_offset_rich_header);

  if (auto res_xor_key = stream.peek<uint32_t>(end_offset_rich_header + sizeof(details::Rich_Magic))) {
    rich_header->key(*res_xor_key);
  } else {
    return make_error_code(lief_errors::read_error);
  }

  const uint32_t xor_key = rich_header->key();
  LIEF_DEBUG("XOR key: 0x{:x}", xor_key);

  int64_t curent_offset = end_offset_rich_header - sizeof(details::Rich_Magic);

  std::vector<uint32_t> values;
  values.reserve(dos_stub.size() / sizeof(uint32_t));

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

    const uint16_t build_number = value & 0xFFFF;
    const uint16_t id           = (value >> 16) & 0xFFFF;

    LIEF_DEBUG("ID:           0x{:04x}", id);
    LIEF_DEBUG("Build Number: 0x{:04x}", build_number);
    LIEF_DEBUG("Count:        0x{:d}", count);

    rich_header->add_entry(id, build_number, count);
  }

  binary_->rich_header_ = std::move(rich_header);
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
    const uint32_t offset = raw_sec.PointerToRawData;
    if (offset > 0) {
      first_section_offset = std::min(first_section_offset, offset);
    }

    size_to_read = raw_sec.VirtualSize > 0 ?
                   std::min(raw_sec.VirtualSize, raw_sec.SizeOfRawData) : // According to Corkami
                   raw_sec.SizeOfRawData;

    if ((offset + size_to_read) > stream_->size()) {
      const uint32_t delta = (offset + size_to_read) - stream_->size();
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
        LIEF_WARN("The padding size of section '{}' is huge. "
                  "Only the first {} bytes will be taken "
                  "into account", section->name(), Parser::MAX_PADDING_SIZE);
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


ok_error_t Parser::parse_relocations() {
  static constexpr size_t MAX_RELOCATION_ENTRIES = 100000;
  LIEF_DEBUG("Parsing relocations");

  const DataDirectory* reloc_dir = binary_->data_directory(DataDirectory::TYPES::BASE_RELOCATION_TABLE);

  if (reloc_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  const uint32_t offset = binary_->rva_to_offset(reloc_dir->RVA());
  const uint32_t max_size = reloc_dir->size();
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
      auto entry = std::make_unique<RelocationEntry>(RelocationEntry::from_raw(this->binary_->header().machine(), *res_entry));
      entry->relocation_ = relocation.get();
      relocation->entries_.push_back(std::move(entry));
    }

    binary_->relocations_.push_back(std::move(relocation));
    current_offset += raw_struct.BlockSize;
    res_relocation_headers = stream_->peek<details::pe_base_relocation_block>(current_offset);
  }

  return ok();
}

ok_error_t Parser::parse_resources() {
  LIEF_DEBUG("Parsing resources");
  const DataDirectory* res_dir = binary_->data_directory(DataDirectory::TYPES::RESOURCE_TABLE);

  if (res_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  const uint32_t resources_rva = res_dir->RVA();
  LIEF_DEBUG("Resources RVA: 0x{:04x}", resources_rva);

  const uint32_t offset = binary_->rva_to_offset(resources_rva);
  LIEF_DEBUG("Resources Offset: 0x{:04x}", offset);

  const auto res_directory_table = stream_->peek<details::pe_resource_directory_table>(offset);
  if (!res_directory_table) {
    return make_error_code(lief_errors::read_error);
  }

  binary_->resources_ = parse_resource_node(*res_directory_table, offset, offset);
  return ok();
}

std::unique_ptr<ResourceNode>
Parser::parse_resource_node(const details::pe_resource_directory_table& directory_table,
                            uint32_t base_offset, uint32_t current_offset,
                            uint32_t depth)
{
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

ok_error_t Parser::parse_string_table() {
  LIEF_DEBUG("Parsing string table");
  uint32_t string_table_offset =
    binary_->header().pointerto_symbol_table() +
    binary_->header().numberof_symbols() * details::sizes::SYMBOL_16;

  auto res_size = stream_->peek<uint32_t>(string_table_offset);
  if (!res_size) {
    return make_error_code(res_size.error());
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


ok_error_t Parser::parse_symbols() {
  LIEF_DEBUG("Parsing symbols");
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
        binary_->header().numberof_symbols() * details::sizes::SYMBOL_16 +
        raw_symbol.Name.Name.Offset;
      auto res_string = stream_->peek_string_at(offset_name, stream_max_size - offset_name);
      if (res_string) {
        symbol.name_ = std::move(*res_string);
      }
    }

    if (symbol.section_number() > 0 &&
        static_cast<uint32_t>(symbol.section_number()) <= binary_->sections_.size()) {
      symbol.section_ = binary_->sections_[symbol.section_number()-1].get();
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

      current_offset += details::sizes::SYMBOL_16;
    }

    current_offset += details::sizes::SYMBOL_16;
    idx += 1 + raw_symbol.NumberOfAuxSymbols;
    binary_->symbols_.push_back(std::move(symbol));
  }

  return ok();
}


ok_error_t Parser::parse_debug() {
  LIEF_DEBUG("Parsing debug directory");

  DataDirectory* dir = binary_->data_directory(DataDirectory::TYPES::DEBUG_DIR);
  if (dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  const uint32_t debug_rva = dir->RVA();
  uint32_t debug_off       = binary_->rva_to_offset(debug_rva);
  const uint32_t debug_sz  = dir->size();
  const uint32_t debug_end = debug_off + debug_sz;

  stream_->setpos(debug_off);
  while (stream_->pos() < debug_end) {
    auto res = stream_->read<details::pe_debug>();
    if (!res) {
      break;
    }
    const auto type = static_cast<Debug::TYPES>(res->Type);
    LIEF_DEBUG("Type is: {}", to_string(type));
    switch (type) {
      case Debug::TYPES::CODEVIEW:
        {
          if (std::unique_ptr<Debug> cv = parse_code_view(*res)) {
            binary_->debug_.push_back(std::move(cv));
          } else {
            LIEF_WARN("Can't parse PE CodeView");
          }
          break;
        }

      case Debug::TYPES::POGO:
        {
          if (std::unique_ptr<Debug> pogo = parse_pogo(*res)) {
            binary_->debug_.push_back(std::move(pogo));
          } else {
            LIEF_WARN("Can't parse PE POGO");
          }
          break;
        }

      case Debug::TYPES::REPRO:
        {
          if (std::unique_ptr<Debug> repro = parse_repro(*res)) {
            binary_->debug_.push_back(std::move(repro));
          } else {
            LIEF_WARN("Can't parse PE Repro");
          }
          break;
        }

      default:
        {
          binary_->debug_.push_back(std::make_unique<Debug>(*res));
          break;
        }
    }
  }
  return ok();
}

std::unique_ptr<Debug> Parser::parse_code_view(const details::pe_debug& debug_info) {
  LIEF_DEBUG("Parsing Debug Code View");
  const uint32_t debug_off = debug_info.PointerToRawData;

  ScopedStream sscoped(*stream_, debug_off);

  auto res_sig = sscoped->peek<uint32_t>(debug_off);
  if (!res_sig) {
    return nullptr;
  }

  const auto signature = static_cast<CodeView::SIGNATURES>(*res_sig);
  auto default_value = std::make_unique<CodeView>(debug_info, signature);

  switch (signature) {
    case CodeView::SIGNATURES::PDB_70:
      {
        const auto pdb_s = sscoped->read<details::pe_pdb_70>();
        if (!pdb_s) {
          return default_value;
        }

        auto cv_pdb70 = std::make_unique<CodeViewPDB>(debug_info, *pdb_s);
        if (auto fname = stream_->read_string()) {
          cv_pdb70->filename(std::move(*fname));
        }
        return cv_pdb70;
      }

    default:
      {
        LIEF_INFO("CodeView signature '{}' is not implemented yet!",
                  to_string(signature));
      }
  }
  return default_value;
}

std::unique_ptr<Debug> Parser::parse_pogo(const details::pe_debug& debug_info) {
  LIEF_DEBUG("Parsing POGO");
  const uint32_t debug_size = debug_info.SizeOfData;
  const uint32_t debug_off  = debug_info.PointerToRawData;
  const uint32_t debug_end  = debug_off + debug_size;

  ScopedStream sscoped(*stream_, debug_off);

  auto res_sig = sscoped->read<uint32_t>();
  if (!res_sig) {
    return nullptr;
  }

  const auto signature = static_cast<Pogo::SIGNATURES>(*res_sig);
  auto pogo = std::make_unique<Pogo>(debug_info, signature);

  switch (signature) {
    case Pogo::SIGNATURES::ZERO: // zero-signature may contain valid entries
    case Pogo::SIGNATURES::LCTG:
      {
        while (sscoped->pos() < debug_end) {
          auto raw = sscoped->read<details::pe_pogo>();
          if (!raw) {
            break;
          }

          PogoEntry entry{raw->start_rva, raw->size};
          if (auto name = sscoped->read_string()) {
            entry.name(std::move(*name));
          }

          pogo->add(std::move(entry));
          sscoped->align(4);
        }

        return pogo;
      }

    case Pogo::SIGNATURES::UNKNOWN:
    default:
      {
        LIEF_INFO("PGO with signature 0x{:x} is not implemented yet!", *res_sig);
      }
  }
  return pogo;
}

std::unique_ptr<Debug> Parser::parse_repro(const details::pe_debug& debug_info) {
  LIEF_DEBUG("Parsing Debug Repro");
  const uint32_t debug_off  = debug_info.PointerToRawData;

  /* const uint32_t debug_size = debug_info.SizeOfData; */
  /* const uint32_t debug_end  = debug_off + debug_size; */
  ScopedStream sscoped(*stream_, debug_off);

  auto res_size = sscoped->read<uint32_t>();
  if (!res_size) {
    return nullptr;
  }
  LIEF_DEBUG("Size: 0x{:x}", *res_size);

  std::vector<uint8_t> hash;
  if (!sscoped->read_data(hash, *res_size)) {
    LIEF_INFO("Can't read debug reproducible build hash");
  }

  return std::make_unique<Repro>(debug_info, std::move(hash));
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


ok_error_t Parser::parse_exports() {
  LIEF_DEBUG("Parsing exports");
  static constexpr uint32_t NB_ENTRIES_LIMIT   = 0x1000000;
  static constexpr size_t MAX_EXPORT_NAME_SIZE = 4096; // Because of C++ mangling

  struct range_t {
    uint32_t start;
    uint32_t end;
  };
  const DataDirectory* export_dir = binary_->data_directory(DataDirectory::TYPES::EXPORT_TABLE);

  if (export_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  uint32_t exports_rva    = export_dir->RVA();
  uint32_t exports_size   = export_dir->size();
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

  auto export_object = std::make_unique<Export>(export_dir_tbl);
  uint32_t name_offset = binary_->rva_to_offset(export_dir_tbl.NameRVA);
  if (auto res_name = stream_->peek_string_at(name_offset, Parser::MAX_DLL_NAME_SIZE)) {
    std::string name = *res_name;
    if (is_valid_dll_name(name)) {
      export_object->name_ = std::move(name);
      LIEF_DEBUG("Export name {}@0x{:x}", export_object->name_, name_offset);
    } else {
      if (name.empty()) {
        LIEF_DEBUG("Export name is empty");
      } else {
        LIEF_DEBUG("'{}' is not a valid export name", printable_string(name));
      }
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
      export_object->entries_.push_back(std::move(entry));
    }
  }

  binary_->export_ = std::move(export_object);
  return ok();
}

ok_error_t Parser::parse_signature() {
  LIEF_DEBUG("Parsing signature");
  static constexpr size_t SIZEOF_HEADER = 8;

  /*** /!\ In this data directory, RVA is used as an **OFFSET** /!\ ****/
  /*********************************************************************/
  const DataDirectory* cert_dir = binary_->data_directory(DataDirectory::TYPES::CERTIFICATE_TABLE);
  if (cert_dir == nullptr) {
    return make_error_code(lief_errors::not_found);
  }

  const uint32_t signature_offset  = cert_dir->RVA();
  const uint32_t signature_size    = cert_dir->size();
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
      return make_error_code(res.error());
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
  LIEF_DEBUG("Parsing Overlay");
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

std::unique_ptr<Binary> Parser::parse(const std::string& filename,
                                      const ParserConfig& conf) {
  if (!is_pe(filename)) {
    return nullptr;
  }
  Parser parser{filename};
  parser.init(conf);
  return std::move(parser.binary_);
}

std::unique_ptr<Binary> Parser::parse(std::vector<uint8_t> data,
                                      const ParserConfig& conf) {
  if (!is_pe(data)) {
    return nullptr;
  }
  Parser parser{std::move(data)};
  parser.init(conf);
  return std::move(parser.binary_);
}

std::unique_ptr<Binary> Parser::parse(std::unique_ptr<BinaryStream> stream,
                                      const ParserConfig& conf) {
  if (!is_pe(*stream)) {
    return nullptr;
  }

  Parser parser{std::move(stream)};
  parser.init(conf);
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
