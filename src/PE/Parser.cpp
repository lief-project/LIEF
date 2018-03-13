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

#include "LIEF/logging++.hpp"

#include "LIEF/filesystem/filesystem.h"
#include "LIEF/exception.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"


#include "LIEF/PE/CodeViewPDB.hpp"

#include "LIEF/PE/Parser.hpp"
#include "Parser.tcc"

#include "LIEF/PE/utils.hpp"

#include "signature/pkcs7.h"

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

  VLOG(VDEBUG) << "Size of dos stub: " << std::hex << sizeof_dos_stub;

  const uint8_t* ptr_to_dos_stub = reinterpret_cast<const uint8_t*>(this->stream_->read(
          sizeof(pe_dos_header),
          sizeof_dos_stub));
  this->binary_->dos_stub_ = {ptr_to_dos_stub, ptr_to_dos_stub + sizeof_dos_stub};
}


void Parser::parse_rich_header(void) {
  VLOG(VDEBUG) << "Parsing Rich Header";
  const std::vector<uint8_t>& dos_stub = this->binary_->dos_stub();
  VectorStream stream{dos_stub};
  auto&& it_rich = std::search(
      std::begin(dos_stub),
      std::end(dos_stub),
      std::begin(Rich_Magic),
      std::end(Rich_Magic));

  if (it_rich == std::end(dos_stub)) {
    VLOG(VDEBUG) << "Rich header not found";
    return;
  }

  this->binary_->has_rich_header_ = true;

  const uint64_t end_offset_rich_header = std::distance(std::begin(dos_stub), it_rich);
  VLOG(VDEBUG) << "Offset to rich header: " << std::hex << end_offset_rich_header;

  const uint32_t xor_key = stream.read_integer<uint32_t>(end_offset_rich_header + sizeof(Rich_Magic));
  this->binary_->rich_header().key(xor_key);
  VLOG(VDEBUG) << "XOR Key: " << std::hex << xor_key;


  uint64_t curent_offset = end_offset_rich_header - sizeof(Rich_Magic);
  std::vector<uint32_t> values;
  values.reserve(dos_stub.size() / sizeof(uint32_t));

  uint32_t count = 0;
  uint32_t value = 0;

  while (value != DanS_Magic_number and count != DanS_Magic_number) {
    try {
      count = stream.read_integer<uint32_t>(curent_offset) ^ xor_key;
      curent_offset -= sizeof(uint32_t);

      value = stream.read_integer<uint32_t>(curent_offset) ^ xor_key;
      curent_offset -= sizeof(uint32_t);
    } catch (const read_out_of_bound&) {
      throw corrupted("Rich Header corrupted");
    }

    if (value == DanS_Magic_number or count == DanS_Magic_number) {
      break;
    }

    uint16_t build_number = value & 0xFFFF;
    uint16_t id = (value >> 16) & 0xFFFF;

    VLOG(VDEBUG) << "ID: "           << std::hex << id << " "
               << "Build Number: " << std::hex << build_number << " "
               << "Count: "        << std::dec << count;

    this->binary_->rich_header().add_entry(id, build_number, count);
  }

  VLOG(VDEBUG) << this->binary_->rich_header();



}




//
// parse PE sections
//
// TODO: Check offset etc
void Parser::parse_sections(void) {

  VLOG(VDEBUG) << "[+] Parsing sections";

  const uint32_t sections_offset  =
    this->binary_->dos_header().addressof_new_exeheader() +
    sizeof(pe_header) +
    this->binary_->header().sizeof_optional_header();

  uint32_t first_section_offset = -1u;

  const uint32_t numberof_sections = this->binary_->header().numberof_sections();
  const pe_section* sections = [&]() {
    try {
      return reinterpret_cast<const pe_section*>(
        this->stream_->read(sections_offset, numberof_sections * sizeof(pe_section)));
    } catch (const read_out_of_bound&) {
      throw corrupted("Sections corrupted");
    }
  }();

  for (size_t i = 0; i < numberof_sections; ++i) {
    std::unique_ptr<Section> section{new Section{&sections[i]}};

    uint32_t size_to_read = 0;
    uint32_t offset = sections[i].PointerToRawData;
    first_section_offset = std::min(first_section_offset, offset);

    if (sections[i].VirtualSize > 0) {
      size_to_read = std::min(sections[i].VirtualSize, sections[i].SizeOfRawData); // According to Corkami
    } else {
      size_to_read = sections[i].SizeOfRawData;
    }

    if ((offset + size_to_read) > this->stream_->size()) {
      uint32_t delta = (offset + size_to_read) - this->stream_->size();
      size_to_read = size_to_read - delta;
    }


    try {
      if (size_to_read > Parser::MAX_DATA_SIZE) {
        LOG(WARNING) << "Section '" << section->name() << "' data is too large!";
      } else {
        const uint8_t* ptr_to_rawdata = reinterpret_cast<const uint8_t*>(this->stream_->read(
          offset,
          size_to_read));

        section->content_ = {
          ptr_to_rawdata,
          ptr_to_rawdata + size_to_read
        };
      }
    } catch (const std::bad_alloc& e) {
      LOG(WARNING) << "Section " << section->name() << " corrupted: " << e.what();
    } catch (const read_out_of_bound& e) {
      LOG(WARNING) << "Section " << section->name() << " corrupted: " << e.what();
    }
    this->binary_->sections_.push_back(section.release());
  }
  const uint32_t last_section_header_offset = sections_offset + numberof_sections * sizeof(pe_section);
  this->binary_->available_sections_space_ = (first_section_offset - last_section_header_offset) / sizeof(pe_section) - 1;
  VLOG(VDEBUG) << "Number of sections that could be added: " << std::dec << this->binary_->available_sections_space_;
}


//
// parse relocations
//
void Parser::parse_relocations(void) {
  VLOG(VDEBUG) << "[+] Parsing relocations";

  this->binary_->has_relocations_ = true;

  const uint32_t offset = this->binary_->rva_to_offset(
      this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA());

  const uint32_t max_size = this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size();
  const uint32_t max_offset = offset + max_size;

  const pe_base_relocation_block* relocation_headers = reinterpret_cast<const pe_base_relocation_block*>(
      this->stream_->read(offset, sizeof(pe_base_relocation_block)));


  uint32_t current_offset = offset;
  while (current_offset < max_offset and relocation_headers->PageRVA != 0) {
    std::unique_ptr<Relocation> relocation{new Relocation{relocation_headers}};

    if (relocation_headers->BlockSize < sizeof(pe_base_relocation_block)) {
      throw corrupted("Relocation corrupted: BlockSize is too small");
    } else if (relocation_headers->BlockSize > this->binary_->optional_header().sizeof_image()) {
      throw corrupted("Relocation corrupted: BlockSize is out of bound the binary's virtual size");
    }

    const uint32_t numberof_entries = (relocation_headers->BlockSize - sizeof(pe_base_relocation_block)) / sizeof(uint16_t);
    const uint16_t* entries = reinterpret_cast<const uint16_t*>(
        this->stream_->read(current_offset + sizeof(pe_base_relocation_block), relocation_headers->BlockSize - sizeof(pe_base_relocation_block)));
    for (size_t i = 0; i < numberof_entries; ++i) {
      std::unique_ptr<RelocationEntry> entry{new RelocationEntry{entries[i]}};
      entry->relocation_ = relocation.get();
      relocation->entries_.push_back(entry.release());
    }

    this->binary_->relocations_.push_back(relocation.release());

    current_offset += relocation_headers->BlockSize;

    relocation_headers = reinterpret_cast<const pe_base_relocation_block*>(
      this->stream_->read(current_offset, sizeof(pe_base_relocation_block)));
  }
}


//
// parse ressources
//
void Parser::parse_resources(void) {
  VLOG(VDEBUG) << "[+] Parsing resources";

  this->binary_->has_resources_ = true;

  const uint32_t resources_rva = this->binary_->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA();
  VLOG(VDEBUG) << "Resources RVA: 0x" << std::hex << resources_rva;

  const uint32_t offset = this->binary_->rva_to_offset(resources_rva);
  VLOG(VDEBUG) << "Resources Offset: 0x" << std::hex << offset;

  const pe_resource_directory_table* directory_table = reinterpret_cast<const pe_resource_directory_table*>(
      this->stream_->read(offset, sizeof(pe_resource_directory_table)));

  this->binary_->resources_ = this->parse_resource_node(directory_table, offset, offset);
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
  const pe_resource_directory_entries* entries_array = reinterpret_cast<const pe_resource_directory_entries*>(
      this->stream_->read(directory_array_offset, sizeof(pe_resource_directory_entries)));

  std::unique_ptr<ResourceDirectory> directory{new ResourceDirectory{directory_table}};

  directory->depth_ = depth;

  // Iterate over the childs
  for (uint32_t idx = 0; idx < (numberof_name_entries + numberof_ID_entries); ++idx) {

    uint32_t data_rva = entries_array->RVA;
    uint32_t id       = entries_array->NameID.IntegerID;

    directory_array_offset += sizeof(pe_resource_directory_entries);
    entries_array = reinterpret_cast<const pe_resource_directory_entries*>(
      this->stream_->read(directory_array_offset, sizeof(pe_resource_directory_entries)));

    std::u16string name;

    // Get the resource name
    if (id & 0x80000000) {
      uint32_t offset = id & (~ 0x80000000);
      uint32_t string_offset = base_offset + offset;
      try {
        const uint16_t length = *reinterpret_cast<const uint16_t*>(
            this->stream_->read(string_offset, sizeof(uint16_t)));

        if (length > 100) {
          VLOG(VDEBUG) << "Size: " << std::dec << length;
          throw LIEF::corrupted("Size error");
        }

        name = std::u16string{reinterpret_cast<const char16_t*>(
            this->stream_->read(
              base_offset + offset + sizeof(uint16_t),
              length * sizeof(uint16_t))),
             length};
      } catch (const LIEF::read_out_of_bound&) {
        LOG(WARNING) << "Resource name is corrupted";
      }
    }

    if ((0x80000000 & data_rva) == 0) { // We are on a leaf
      uint32_t offset = base_offset + data_rva;

      try {
        const pe_resource_data_entry *data_entry = reinterpret_cast<const pe_resource_data_entry*>(
            this->stream_->read(offset, sizeof(pe_resource_data_entry)));

        uint32_t content_offset = this->binary_->rva_to_offset(data_entry->DataRVA);
        uint32_t content_size   = data_entry->Size;
        uint32_t code_page      = data_entry->Codepage;

        const uint8_t* content_ptr = reinterpret_cast<const uint8_t*>(
            this->stream_->read(content_offset, content_size));

        std::vector<uint8_t> content = {
          content_ptr,
          content_ptr + content_size};

        std::unique_ptr<ResourceNode> node{new ResourceData{content, code_page}};

        node->depth_ = depth + 1;
        node->id(id);
        node->name(name);
        dynamic_cast<ResourceData*>(node.get())->offset_ = content_offset;

        directory->childs_.push_back(node.release());
      } catch (const LIEF::read_out_of_bound&) { // Corrupted
        LOG(WARNING) << "The leaf is corrupted";
        break;
      }
    } else { // We are on a directory
      const uint32_t directory_rva = data_rva & (~ 0x80000000);
      const uint32_t offset        = base_offset + directory_rva;
      try {
        const pe_resource_directory_table* nextDirectoryTable = reinterpret_cast<const pe_resource_directory_table*>(
            this->stream_->read(offset, sizeof(pe_resource_directory_table)));
        if (this->resource_visited_.count(offset) > 0) {
          LOG(WARNING) << "Infinite loop detected on resources";
          break;
        }
        this->resource_visited_.insert(offset);

        std::unique_ptr<ResourceNode> node{this->parse_resource_node(nextDirectoryTable, base_offset, offset, depth + 1)};
        node->id(id);
        node->name(name);
        directory->childs_.push_back(node.release());
      } catch (const LIEF::read_out_of_bound&) { // Corrupted
        LOG(WARNING) << "The directory is corrupted";
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
  VLOG(VDEBUG) << "[+] Parsing string table";
  uint32_t stringTableOffset =
    this->binary_->header().pointerto_symbol_table() +
    this->binary_->header().numberof_symbols() * STRUCT_SIZES::Symbol16Size;

  uint32_t size = *reinterpret_cast<const uint32_t*>(
      this->stream_->read(stringTableOffset, sizeof(uint32_t))) - 4;

  uint32_t currentSize = 0;

  const char *table = this->stream_->read_string(stringTableOffset + 4);

  while (currentSize < size) {
    std::string name{table + currentSize};
    currentSize += name.size() + 1;
    this->binary_->strings_table_.push_back(name);
  }
}


//
// parse Symbols
//
void Parser::parse_symbols(void) {
  VLOG(VDEBUG) << "[+] Parsing symbols";
  uint32_t symbolTableOffset = this->binary_->header().pointerto_symbol_table();
  uint32_t numberOfSymbols   = this->binary_->header().numberof_symbols();
  uint32_t offsetToNextSymbol = symbolTableOffset;

  uint32_t idx = 0;
  while (idx < numberOfSymbols) {
    //if (offsetToNextSymbol >= this->rawBinary_.size()) {
    //  throw LIEF::exception("Parser::parse_symbols(): Symbol offset corrupted",
    //      LIEF::EXCEPTION_TYPES::CORRUPTED_OFFSET);
    //}
    //TODO: try catch
    pe_symbol *symbolPtr;
    try {
      symbolPtr = reinterpret_cast<pe_symbol*>(const_cast<void*>(
        this->stream_->read(offsetToNextSymbol, sizeof(pe_symbol))));

    } catch (const LIEF::read_out_of_bound&) { // Corrupted
      LOG(WARNING) << "Symbol is corrupted (idx: " << std::dec << idx << ")";
      break;
    }


    Symbol symbol{reinterpret_cast<const pe_symbol*>(symbolPtr)};

    std::string name;
    if ((symbolPtr->Name.Name.Zeroes & 0xffff) != 0) {
      std::string shortname{symbolPtr->Name.ShortName, sizeof(symbolPtr->Name.ShortName)};
      name = shortname.c_str();
    } else {
      uint32_t offset = symbolPtr->Name.Name.Offset;
      uint64_t offset_name =
        this->binary_->header().pointerto_symbol_table() +
        this->binary_->header().numberof_symbols() * STRUCT_SIZES::Symbol16Size +
        offset;
      try {
        symbol.name_ = this->stream_->get_string(offset_name);
      } catch (const LIEF::read_out_of_bound&) { // Corrupted
        LOG(WARNING) << "Symbol name is corrupted";
      }
    }
    if (symbol.section_number() > 0 and
        static_cast<uint32_t>(symbol.section_number()) < this->binary_->sections_.size()) {
      symbol.section_ = this->binary_->sections_[symbol.section_number()];
    }

    for (uint32_t i = 0; i < symbolPtr->NumberOfAuxSymbols; ++i) {
      // Auxiliary Format 1: Function Definitions
      // * Storage class : EXTERNAL
      // * Type          : 0x20 (Function)
      // * Section Number: > 0
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL and
          symbol.type() == 0x20 and symbol.section_number() > 0) {
        VLOG(VDEBUG) << "Format1";
      }


      // Auxiliary Format 2: .bf and .ef Symbols
      // * Storage class : FUNCTION
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_FUNCTION) {
        VLOG(VDEBUG) << "Function";
      }

      // Auxiliary Format 3: Weak Externals
      // * Storage class : EXTERNAL
      // * Section Number: UNDEF
      // * Value         : 0
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_EXTERNAL and
          symbol.value() == 0 and static_cast<SYMBOL_SECTION_NUMBER>(symbol.section_number()) == SYMBOL_SECTION_NUMBER::IMAGE_SYM_UNDEFINED) {
        VLOG(VDEBUG) << "Format 3";
      }

      // Auxiliary Format 4: Files
      // * Storage class     : FILE
      // * Name **SHOULD** be: .file
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_FILE) {
        VLOG(VDEBUG) << "Format 4";
        //std::cout << reinterpret_cast<char*>(
      }

      // Auxiliary Format 5: Section Definitions
      // * Storage class     : STATIC
      if (symbol.storage_class() == SYMBOL_STORAGE_CLASS::IMAGE_SYM_CLASS_STATIC) {
        VLOG(VDEBUG) << "Format 5";
      }

      offsetToNextSymbol += STRUCT_SIZES::Symbol16Size;
    }

    offsetToNextSymbol += STRUCT_SIZES::Symbol16Size;
    idx += 1 + symbolPtr->NumberOfAuxSymbols;
    this->binary_->symbols_.push_back(std::move(symbol));
  }


}


//
// parse Debug
//

void Parser::parse_debug(void) {
  VLOG(VDEBUG) << "[+] Parsing Debug";

  this->binary_->has_debug_ = true;

  uint32_t debugRVA    = this->binary_->data_directory(DATA_DIRECTORY::DEBUG).RVA();
  uint32_t debugoffset = this->binary_->rva_to_offset(debugRVA);
  //uint32_t debugsize   = this->binary_->dataDirectories_[DATA_DIRECTORY::DEBUG]->size();

  const pe_debug* debug_struct = reinterpret_cast<const pe_debug*>(
      this->stream_->read(debugoffset, sizeof(pe_debug)));

  this->binary_->debug_ = debug_struct;

  DEBUG_TYPES type = this->binary_->debug().type();

  switch (type) {
    case DEBUG_TYPES::IMAGE_DEBUG_TYPE_CODEVIEW:
      {
        this->parse_debug_code_view();
      }
    default:
      {
      }
  }
}

void Parser::parse_debug_code_view() {
  VLOG(VDEBUG) << "Parsing Debug Code View";
  Debug& debug_info = this->binary_->debug();

  const uint32_t debug_off = debug_info.pointerto_rawdata();
  const CODE_VIEW_SIGNATURES signature = static_cast<CODE_VIEW_SIGNATURES>(this->stream_->read_integer<uint32_t>(debug_off));

  switch (signature) {
    case CODE_VIEW_SIGNATURES::CVS_PDB_70:
      {

        const pe_pdb_70* pdb_s = reinterpret_cast<const pe_pdb_70*>(
            this->stream_->read(debug_off, sizeof(pe_pdb_70)));

        std::string path = this->stream_->get_string(debug_off + offsetof(pe_pdb_70, filename));

        CodeViewPDB::signature_t sig;
        std::copy(std::begin(pdb_s->signature), std::end(pdb_s->signature), std::begin(sig));
        std::unique_ptr<CodeViewPDB> codeview{new CodeViewPDB{CodeViewPDB::from_pdb70(sig, pdb_s->age, path)}};

        debug_info.code_view_ = codeview.release();
        break;
      }

    default:
      {
        LOG(WARNING) << to_string(signature) << " is not implemented yet!";
      }
  }


}


//
// parse Export
//
void Parser::parse_exports(void) {
  VLOG(VDEBUG) << "[+] Parsing exports";

  this->binary_->has_exports_ = true;

  uint32_t exports_rva    = this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).RVA();
  uint32_t exports_offset = this->binary_->rva_to_offset(exports_rva);
  uint32_t exports_size   = this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).size();
  std::pair<uint32_t, uint32_t> range = {exports_rva, exports_rva + exports_size};

  // First Export directory
  const pe_export_directory_table* export_directory_table = reinterpret_cast<const pe_export_directory_table*>(
      this->stream_->read(exports_offset, sizeof(pe_export_directory_table)));

  Export export_object = {export_directory_table};
  uint32_t name_offset = this->binary_->rva_to_offset(export_directory_table->NameRVA);

  try {
    export_object.name_  = this->stream_->get_string(name_offset);
  } catch (const LIEF::read_out_of_bound& e) {
    LOG(WARNING) << e.what();
  }


  // Parse Ordinal name table
  uint32_t ordinal_table_offset  = this->binary_->rva_to_offset(export_directory_table->OrdinalTableRVA);
  const uint32_t nbof_name_ptr = export_directory_table->NumberOfNamePointers;
  const uint16_t *ordinal_table = reinterpret_cast<const uint16_t*>(
      this->stream_->read(ordinal_table_offset, nbof_name_ptr * sizeof(uint16_t)));


  // Parse Address table
  uint32_t address_table_offset = this->binary_->rva_to_offset(export_directory_table->ExportAddressTableRVA);
  const uint32_t nbof_addr_entries = export_directory_table->AddressTableEntries;
  const uint32_t *address_table = reinterpret_cast<const uint32_t*>(
      this->stream_->read(address_table_offset, nbof_addr_entries * sizeof(uint32_t)));

  if (nbof_addr_entries < nbof_name_ptr) {
    throw corrupted("More exported names than addresses");
  }

  // Parse Export name table
  uint32_t name_table_offset = this->binary_->rva_to_offset(export_directory_table->NamePointerRVA);
  const uint32_t *name_table  = reinterpret_cast<const uint32_t*>(
      this->stream_->read(name_table_offset, nbof_name_ptr * sizeof(uint32_t)));



  // Export address table (EXTERN)
  // =============================
  for (size_t i = 0; i < nbof_addr_entries; ++i) {
    const uint32_t value = address_table[i];
    // If value is inside export directory => 'external' function
    if (value >= std::get<0>(range) and value < std::get<1>(range)) {
      uint32_t name_offset = this->binary_->rva_to_offset(value);

      ExportEntry entry;
      try {
        entry.name_ = this->stream_->get_string(name_offset);
      } catch (const LIEF::read_out_of_bound& e) {
        LOG(WARNING) << e.what();
      }
      entry.address_   = 0;
      entry.is_extern_ = true;
      entry.ordinal_   = i + export_directory_table->OrdinalBase;
      export_object.entries_.push_back(std::move(entry));

    }
  }


  for (size_t i = 0; i < nbof_name_ptr; ++i) {
    if (ordinal_table[i] >= nbof_addr_entries) {
      throw corrupted("Export ordinal is outside the address table");
    }

    uint32_t name_offset = this->binary_->rva_to_offset(name_table[i]);
    std::string name  = "";
    try {
      name = this->stream_->get_string(name_offset);
    } catch (const LIEF::read_out_of_bound& e) {
      LOG(WARNING) << e.what();
    }

    ExportEntry entry;
    entry.name_      = name;
    entry.is_extern_ = false;
    entry.ordinal_   = ordinal_table[i] + export_directory_table->OrdinalBase;
    entry.address_   = address_table[ordinal_table[i]];
    export_object.entries_.push_back(std::move(entry));
  }

  this->binary_->export_ = std::move(export_object);

}

void Parser::parse_signature(void) {
  VLOG(VDEBUG) << "[+] Parsing signature";

  /*** /!\ In this data directory, RVA is used as an **OFFSET** /!\ ****/
  /*********************************************************************/
  const uint32_t signature_offset  = this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).RVA();
  const uint32_t signature_size = this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).size();
  VLOG(VDEBUG) << "Signature Offset: 0x" << std::hex << signature_offset;
  VLOG(VDEBUG) << "Signature Size: 0x" << std::hex << signature_size;

  const uint8_t* signature_ptr = reinterpret_cast<const uint8_t*>(this->stream_->read(signature_offset, signature_size));
  std::vector<uint8_t> raw_signature = {signature_ptr, signature_ptr + signature_size};

  //TODO: Deal with header (+8)
#if 0
  const uint8_t* signature_ptr = reinterpret_cast<const uint8_t*>(this->stream_->read(signature_offset + 8, signature_size - 8));
  const uint8_t* end = signature_ptr + signature_size - 8;
  Signature signature;
  mbedtls_asn1_buf buf;
  int ret = 0;
  size_t tag;

  uint8_t* p = const_cast<uint8_t*>(signature_ptr);

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  buf.tag = *p;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &buf.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Error while reading tag");
  }

  buf.p = p;
  char oid_str[256] = { 0 };
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &buf);
  VLOG(VDEBUG) << "OID (signedData): " << oid_str;
  p += buf.len;


  if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_SIGNED_DATA, &buf) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // Version
  // =======
  int version;
  if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0) {
    throw corrupted("Signature corrupted");
  }

  VLOG(VDEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "Version should be equal to 1 (" << std::dec << version << ")";
  signature.version_ = static_cast<uint32_t>(version);


  // Algo (digestAlgorithms)
  // =======================
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
    throw corrupted("Signature corrupted");
  }

  mbedtls_asn1_buf alg_oid;
  if ((ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }
  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);

  VLOG(VDEBUG) << "digestAlgorithms: " << oid_str;

  signature.digest_algorithm_ = oid_str;

  // contentInfo
  // |_ contentType
  // |_ content (SpcIndirectDataContent)
  // ===================================
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }
  ContentInfo content_info;


  // Content type
  // ------------
  mbedtls_asn1_buf content_type_oid;
  content_type_oid.tag = *p;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.p = p;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

  if (MBEDTLS_OID_CMP(MBEDTLS_SPC_INDIRECT_DATA_OBJID, &content_type_oid) != 0) {
    throw corrupted(std::string(oid_str) + " is not SPC_INDIRECT_DATA_OBJID");
  }
  VLOG(VDEBUG) << "contentType: " << oid_str;
  content_info.content_type_ = oid_str;
  p += content_type_oid.len;

  // content - SpcIndirectDataContent
  // |_ SpcAttributeTypeAndOptionalValue
  // |_ DigestInfo
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  VLOG(VDEBUG) << "Parsing SpcIndirectDataContent (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // SpcAttributeTypeAndOptionalValue
  // |_ SPC_PE_IMAGE_DATAOBJ
  // |_ SpcPeImageData
  // ++++++++++++++++++++++++++++++++
  VLOG(VDEBUG) << "Parsing SpcAttributeTypeAndOptionalValue (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *p;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_type_oid.p = p;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  VLOG(VDEBUG) << "SpcAttributeTypeAndOptionalValue->type " << oid_str;

  content_info.type_ = oid_str;
  p += content_type_oid.len;

  // SpcPeImageData
  // |_ SpcPeImageFlags
  // |_ SpcLink
  // ++++++++++++++
  VLOG(VDEBUG) << "Parsing SpcPeImageData (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // SpcPeImageFlags
  // ^^^^^^^^^^^^^^^
  VLOG(VDEBUG) << "Parsing SpcPeImageFlags (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_BIT_STRING)) != 0) {
    throw corrupted("Signature corrupted");
  }
  p += tag; // skip

  // SpcLink
  // ^^^^^^^
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }
  p += tag; // skip

  // DigestInfo
  // ++++++++++
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  VLOG(VDEBUG) << "DigestInfo->digestAlgorithm: " << oid_str;

  content_info.digest_algorithm_ = oid_str;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_info.digest_ = {p, p + tag};

  //TODO: Read hash
  p += tag;

  signature.content_info_ = std::move(content_info);

  // Certificates
  // ============
  VLOG(VDEBUG) << "Parsing Certificates (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  uint8_t* cert_end = p + tag;
  char buffer[1024];
  while (p < cert_end) {
    std::memset(buffer, 0, sizeof(buffer));

    std::unique_ptr<mbedtls_x509_crt> ca{new mbedtls_x509_crt{}};
    mbedtls_x509_crt_init(ca);
    mbedtls_x509_crt_parse_der(ca, p, end - p);


    mbedtls_x509_crt_info(buffer, sizeof(buffer), "", ca.get());
    VLOG(VDEBUG) << std::endl << buffer << std::endl;

    signature.certificates_.emplace_back(ca.release());

    if (ca->raw.len <= 0) {
      break;
    }
    p += ca->raw.len;
  }


  // signerInfo
  // ==========
  SignerInfo signer_info;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0) {
    throw corrupted("Signature corrupted");
  }

  VLOG(VDEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "SignerInfo's version should be equal to 1 (" << std::dec << version << ")";
  signer_info.version_ = version;

  // issuerAndSerialNumber
  // ---------------------
  VLOG(VDEBUG) << "Parsing issuerAndSerialNumber (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // Name
  // ~~~~
  std::vector<std::pair<std::string, std::string>> issuer_name;
  uint8_t* p_end = p + tag;
  while(p < p_end) {
    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
      throw corrupted("Signature corrupted");
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
      throw corrupted("Signature corrupted");
    }

    content_type_oid.tag = *p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
      throw corrupted("Signature corrupted");
    }
    content_type_oid.p = p;

    std::memset(oid_str, 0, sizeof(oid_str));
    mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

    VLOG(VDEBUG) << "Component ID: " << oid_str;
    p += content_type_oid.len;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_PRINTABLE_STRING)) != 0) {
      throw corrupted("Signature corrupted");
    }

    std::string name{reinterpret_cast<char*>(p), tag};
    issuer_name.emplace_back(oid_str, name);
    VLOG(VDEBUG) << "Name: " << name;
    p += tag;
  }

  // CertificateSerialNumber (issuer SN)
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mbedtls_mpi certificate_number;
  mbedtls_mpi_init(&certificate_number);
  if ((ret = mbedtls_asn1_get_mpi(&p, end, &certificate_number)) != 0) {
    throw corrupted("Signature corrupted");
  }
  std::vector<uint8_t> certificate_sn(mbedtls_mpi_size(&certificate_number), 0);
  mbedtls_mpi_write_binary(&certificate_number, certificate_sn.data(), certificate_sn.size());
  mbedtls_mpi_free(&certificate_number);

  signer_info.issuer_ = {issuer_name, certificate_sn};



  // digestAlgorithm
  // ---------------
  VLOG(VDEBUG) << "Parsing digestAlgorithm (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  VLOG(VDEBUG) << "signerInfo->digestAlgorithm " << oid_str;

  signer_info.digest_algorithm_ = oid_str;

  // authenticatedAttributes
  // |_ contentType
  // |_ messageDigest
  // |_ SpcSpOpusInfo
  // -----------------------
  AuthenticatedAttributes authenticated_attributes;

  VLOG(VDEBUG) << "Parsing authenticatedAttributes (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // contentType (1.2.840.113549.1.9.3)
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *p;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_type_oid.p = p;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

  VLOG(VDEBUG) << oid_str; // 1.2.840.113549.1.9.3 (PKCS #9 contentType)

  p += content_type_oid.len;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *p;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.p = p;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);

  VLOG(VDEBUG) << oid_str; // 1.2.840.113549.1.9.4
  p += content_type_oid.len;
  //authenticated_attributes.content_type_ = oid_str;

  // TODO
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }
  p += tag;


  // messageDigest (Octet string)
  // |_ OID (PKCS #9 Message Disgest)
  // |_ SET -> OCTET STING
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  VLOG(VDEBUG) << "Parsing messageDigest (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *p;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }
  content_type_oid.p = p;

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  VLOG(VDEBUG) << oid_str << " (" << oid_to_string(oid_str) << ")"; // 1.2.840.113549.1.9.4
  p += content_type_oid.len;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted: Can't read 'ASN1_OCTET_STRING'");
  }
  authenticated_attributes.message_digest_ = {p, p + tag};
  p += tag;


  // SpcSpOpusInfo
  // |_ programName (utf16)
  // |_ moreInfo
  // ~~~~~~~~~~~~~~~~~~~~~~
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.tag = *p;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0) {
    throw corrupted("Signature corrupted");
  }

  content_type_oid.p = p;
  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &content_type_oid);
  VLOG(VDEBUG) << oid_str; // 1.3.6.1.4.1.311.2.1.12 (SpcSpOpusInfoObjId)
  p += content_type_oid.len;

  // programName
  // +++++++++++
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
    throw corrupted("Signature corrupted");
  }
  std::u16string progname{reinterpret_cast<char16_t*>(p + 1), tag / 2}; // programName
  authenticated_attributes.program_name_ = progname;
  VLOG(VDEBUG) << "ProgName " << u16tou8(progname);
  p += tag;

  // moreInfo
  // ++++++++
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_BOOLEAN )) != 0) {
    throw corrupted("Signature corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
    throw corrupted("Signature corrupted");
  }

  std::string more_info{reinterpret_cast<char*>(p), tag}; // moreInfo
  authenticated_attributes.more_info_ = more_info;
  VLOG(VDEBUG) << more_info;
  p += tag;

  signer_info.authenticated_attributes_ = std::move(authenticated_attributes);

  // digestEncryptionAlgorithm
  // -------------------------
  if ((ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }
  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  signer_info.signature_algorithm_ = oid_str;

  VLOG(VDEBUG) << "digestEncryptionAlgorithm: " << oid_str;

  // encryptedDigest
  // ---------------
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted");
  }

  signer_info.encrypted_digest_ = {p, p + tag};
  p += tag;

  //TODO:
  // unauthenticatedAttributes


  signature.signer_info_ = std::move(signer_info);
  VLOG(VDEBUG) << "Signature: " << std::endl << signature;
#endif
  this->binary_->signature_ = SignatureParser::parse(raw_signature);
  this->binary_->has_signature_ = true;
}


void Parser::parse_overlay(void) {
  VLOG(VDEBUG) << "Parsing Overlay";
  const uint64_t last_section_offset = std::accumulate(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->offset() + section->size(), offset);
      });

  VLOG(VDEBUG) << "Overlay offset: 0x" << std::hex << last_section_offset;

  if (last_section_offset < this->stream_->size()) {
    const uint64_t overlay_size = this->stream_->size() - last_section_offset;

    VLOG(VDEBUG) << "Overlay size: " << std::dec << overlay_size;

    const uint8_t* ptr_to_overlay = reinterpret_cast<const uint8_t*>(this->stream_->read(
        last_section_offset,
        overlay_size));

    this->binary_->overlay_ = {
        ptr_to_overlay,
        ptr_to_overlay + overlay_size
      };
  } else {
    this->binary_->overlay_ = {};
  }
}

//
// Return the Binary constructed
//
Binary* Parser::parse(const std::string& filename) {
  Parser parser{filename};
  return parser.binary_;
}


Binary* Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  return parser.binary_;
}

}
}
