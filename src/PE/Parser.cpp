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

#include "easylogging++.h"

#include "LIEF/filesystem/filesystem.h"
#include "LIEF/exception.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/signature/Signature.hpp"

#include "LIEF/PE/Parser.hpp"
#include "Parser.tcc"

#include "LIEF/PE/utils.hpp"

#include "pkcs7.h"

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
    this->build<PE32>();
  } else {
    this->build<PE64>();
  }

}

void Parser::build_dos_stub(void) {
  const DosHeader& dos_header = this->binary_->dos_header();
  const uint64_t sizeof_dos_stub = dos_header.addressof_new_exeheader() - sizeof(pe_dos_header);

  const uint8_t* ptr_to_dos_stub = reinterpret_cast<const uint8_t*>(this->stream_->read(
        sizeof(pe_dos_header),
        sizeof_dos_stub));
  this->binary_->dos_stub_ = {ptr_to_dos_stub, ptr_to_dos_stub + sizeof_dos_stub};
}




//
// Build PE sections
//
// TODO: Check offset etc
void Parser::build_sections(void) {

  LOG(DEBUG) << "[+] Parsing sections";

  const uint32_t sections_offset  =
    this->binary_->dos_header().addressof_new_exeheader() +
    sizeof(pe_header) +
    this->binary_->header().sizeof_optional_header();

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
    Section* section = new Section{&sections[i]};

    try {
      const uint8_t* ptr_to_rawdata = reinterpret_cast<const uint8_t*>(this->stream_->read(
        sections[i].PointerToRawData,
        sections[i].SizeOfRawData));

      section->content_ = {
        ptr_to_rawdata,
        ptr_to_rawdata + sections[i].SizeOfRawData
      };
    } catch (const std::bad_alloc& e) {
      LOG(WARNING) << "Section " << section->name() << " corrupted: " << e.what();
    } catch (const read_out_of_bound& e) {
      LOG(WARNING) << "Section " << section->name() << " corrupted: " << e.what();
    }

    this->binary_->sections_.push_back(section);
  }
}


//
// Build relocations
//
void Parser::build_relocations(void) {
  LOG(DEBUG) << "[+] Parsing relocations";

  this->binary_->has_relocations_ = true;

  const uint32_t offset = this->binary_->rva_to_offset(
      this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA());

  const uint32_t max_size = this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size();
  const uint32_t max_offset = offset + max_size;

  const pe_base_relocation_block* relocation_headers = reinterpret_cast<const pe_base_relocation_block*>(
      this->stream_->read(offset, sizeof(pe_base_relocation_block)));


  uint32_t current_offset = offset;
  while (current_offset < max_offset and relocation_headers->PageRVA != 0) {
    Relocation relocation{relocation_headers};

    if (relocation_headers->BlockSize < sizeof(pe_base_relocation_block)) {
      throw corrupted("Relocation corrupted: BlockSize is too small");
    } else if (relocation_headers->BlockSize > this->binary_->optional_header().sizeof_image()) {
      throw corrupted("Relocation corrupted: BlockSize is out of bound the binary's virtual size");
    }

    const uint32_t numberof_entries = (relocation_headers->BlockSize - sizeof(pe_base_relocation_block)) / sizeof(uint16_t);
    const uint16_t* entries = reinterpret_cast<const uint16_t*>(reinterpret_cast<const uint8_t*>(relocation_headers) + sizeof(pe_base_relocation_block));
    for (size_t i = 0; i < numberof_entries; ++i) {
      relocation.entries_.emplace_back(entries[i]);
    }

    this->binary_->relocations_.push_back(relocation);

    current_offset += relocation_headers->BlockSize;

    relocation_headers = reinterpret_cast<const pe_base_relocation_block*>(
      this->stream_->read(current_offset, sizeof(pe_base_relocation_block)));
  }
}


//
// Build ressources
//
void Parser::build_resources(void) {
  LOG(DEBUG) << "[+] Parsing resources";

  this->binary_->has_resources_ = true;

  const uint32_t resources_rva = this->binary_->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA();
  LOG(DEBUG) << "Resources RVA: 0x" << std::hex << resources_rva;

  const uint32_t offset = this->binary_->rva_to_offset(resources_rva);
  LOG(DEBUG) << "Resources Offset: 0x" << std::hex << offset;

  const pe_resource_directory_table* directory_table = reinterpret_cast<const pe_resource_directory_table*>(
      this->stream_->read(offset, sizeof(pe_resource_directory_table)));

  this->binary_->resources_ = this->build_resource_node(directory_table, offset);
}


//
// Build the resources tree
//
ResourceNode* Parser::build_resource_node(
    const pe_resource_directory_table *directory_table,
    uint32_t base_offset,
    uint32_t depth) {

  const uint32_t numberof_ID_entries   = directory_table->NumberOfIDEntries;
  const uint32_t numberof_name_entries = directory_table->NumberOfNameEntries;

  const pe_resource_directory_entries* entries_array = reinterpret_cast<const pe_resource_directory_entries*>(directory_table + 1);

  ResourceDirectory* directory = new ResourceDirectory{directory_table};

  directory->depth_ = depth;

  // Iterate over the childs
  for (uint32_t idx = 0; idx < (numberof_name_entries + numberof_ID_entries); ++idx) {

    uint32_t data_rva = entries_array[idx].RVA;
    uint32_t id        = entries_array[idx].NameID.IntegerID;
    std::u16string name;

    // Get the resource name
    if (id & 0x80000000) {
      uint32_t offset = id & (~ 0x80000000);
      uint32_t string_offset = base_offset + offset;
      try {
        const uint16_t length = *reinterpret_cast<const uint16_t*>(
            this->stream_->read(string_offset, sizeof(uint16_t)));

        if (length > 100) {
          LOG(DEBUG) << "Size: " << std::dec << length;
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

        ResourceNode* node = new ResourceData{content, code_page};

        node->depth_ = depth + 1;
        node->id(id);
        node->name(name);
        dynamic_cast<ResourceData*>(node)->offset_ = content_offset;

        directory->childs_.push_back(node);
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

        ResourceNode* node = this->build_resource_node(nextDirectoryTable, base_offset, depth + 1);
        node->id(id);
        node->name(name);
        directory->childs_.push_back(node);
      } catch (const LIEF::read_out_of_bound&) { // Corrupted
        LOG(WARNING) << "The directory is corrupted";
        break;
      }
    }
  }

  return std::move(directory);
}

//
// Build string table
//
void Parser::build_string_table(void) {
  LOG(DEBUG) << "[+] Parsing string table";
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
// Build Symbols
//
void Parser::build_symbols(void) {
  LOG(DEBUG) << "[+] Parsing symbols";
  uint32_t symbolTableOffset = this->binary_->header().pointerto_symbol_table();
  uint32_t numberOfSymbols   = this->binary_->header().numberof_symbols();
  uint32_t offsetToNextSymbol = symbolTableOffset;

  uint32_t idx = 0;
  while (idx < numberOfSymbols) {
    //if (offsetToNextSymbol >= this->rawBinary_.size()) {
    //  throw LIEF::exception("Parser::build_symbols(): Symbol offset corrupted",
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
      name = symbolPtr->Name.ShortName;
    } else {
      uint32_t offset = symbolPtr->Name.Name.Offset;
      uint64_t offset_name =
        this->binary_->header().pointerto_symbol_table() +
        this->binary_->header().numberof_symbols() * STRUCT_SIZES::Symbol16Size +
        offset;
      try {
        symbol.name_ = this->stream_->read_string(offset_name);
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
      if (symbol.storage_class() == IMAGE_SYM_CLASS_EXTERNAL and
          symbol.type() == 0x20 and symbol.section_number() > 0) {
        LOG(DEBUG) << "Format1";
      }


      // Auxiliary Format 2: .bf and .ef Symbols
      // * Storage class : FUNCTION
      if (symbol.storage_class() == IMAGE_SYM_CLASS_FUNCTION) {
        LOG(DEBUG) << "Function";
      }

      // Auxiliary Format 3: Weak Externals
      // * Storage class : EXTERNAL
      // * Section Number: UNDEF
      // * Value         : 0
      if (symbol.storage_class() == IMAGE_SYM_CLASS_EXTERNAL and
          symbol.value() == 0 and symbol.section_number() == IMAGE_SYM_UNDEFINED) {
        LOG(DEBUG) << "Format 3";
      }

      // Auxiliary Format 4: Files
      // * Storage class     : FILE
      // * Name **SHOULD** be: .file
      if (symbol.storage_class() == IMAGE_SYM_CLASS_FILE) {
        LOG(DEBUG) << "Format 4";
        //std::cout << reinterpret_cast<char*>(
      }

      // Auxiliary Format 5: Section Definitions
      // * Storage class     : STATIC
      if (symbol.storage_class() == IMAGE_SYM_CLASS_STATIC) {
        LOG(DEBUG) << "Format 5";
      }

      offsetToNextSymbol += STRUCT_SIZES::Symbol16Size;
    }

    offsetToNextSymbol += STRUCT_SIZES::Symbol16Size;
    idx += 1 + symbolPtr->NumberOfAuxSymbols;
    this->binary_->symbols_.push_back(std::move(symbol));
  }


}


//
// Build Debug
//

void Parser::build_debug(void) {
  LOG(DEBUG) << "[+] Parsing Debug";

  this->binary_->has_debug_ = true;

  uint32_t debugRVA    = this->binary_->data_directory(DATA_DIRECTORY::DEBUG).RVA();
  uint32_t debugoffset = this->binary_->rva_to_offset(debugRVA);
  //uint32_t debugsize   = this->binary_->dataDirectories_[DATA_DIRECTORY::DEBUG]->size();

  const pe_debug* debug_struct = reinterpret_cast<const pe_debug*>(
      this->stream_->read(debugoffset, sizeof(pe_debug)));

  this->binary_->debug_ = {debug_struct};
}

//
// Build configuration
//
void Parser::build_configuration(void) {
  LOG(DEBUG) << "[+] Parsing Load config";
  this->binary_->has_configuration_ = true;
  //uint32_t offset = rva_to_offset(this->binary_->sectionsList_, this->binary_->dataDirList_[LOAD_CONFIG_TABLE].getRVA());
  //this->binary_->loadConfigure_ = *(reinterpret_cast<LoadConfiguration<uint32_t>*>(this->rawBinary_.data() + offset));
}


//
// Build Export
//
void Parser::build_exports(void) {
  LOG(DEBUG) << "[+] Parsing exports";

  this->binary_->has_exports_ = true;

  uint32_t exportsRVA    = this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).RVA();
  uint32_t exportsOffset = this->binary_->rva_to_offset(exportsRVA);
  uint32_t exportsSize   = this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).size();
  std::pair<uint32_t, uint32_t> range = {exportsOffset, exportsOffset + exportsSize};

  // First Export directory
  const auto* exportDirectoryTable = reinterpret_cast<const pe_export_directory_table*>(
      this->stream_->read(exportsOffset, sizeof(pe_export_directory_table)));

  Export exportObject = {exportDirectoryTable};
  uint32_t nameOffset = this->binary_->rva_to_offset(exportDirectoryTable->NameRVA);

  try {
    exportObject.name_  = this->stream_->read_string(nameOffset);
  } catch (const LIEF::read_out_of_bound& e) {
    LOG(WARNING) << e.what();
    //TODO
  }


  // Parse ordinal name table
  uint32_t ordinalNameTableOffset  = this->binary_->rva_to_offset(exportDirectoryTable->OrdinalTableRVA);
  const uint32_t nbof_name_ptr = exportDirectoryTable->NumberOfNamePointers;
  const uint16_t *ordinalTable     = reinterpret_cast<const uint16_t*>(
      this->stream_->read(ordinalNameTableOffset, nbof_name_ptr * sizeof(uint16_t)));


  // Parse Address table
  uint32_t offsetExportTableAddress = this->binary_->rva_to_offset(
      exportDirectoryTable->ExportAddressTableRVA);
  const uint32_t nbof_addr_entries = exportDirectoryTable->AddressTableEntries;
  const uint32_t *addressTable = reinterpret_cast<const uint32_t*>(
      this->stream_->read(offsetExportTableAddress, nbof_addr_entries * sizeof(uint32_t)));

  for (size_t i = 0; i < nbof_addr_entries; ++i) {
    const uint32_t value = addressTable[i];
    // If value is inside export directory => 'external' function
    if (value >= range.first and value < range.second) {
      uint32_t nameOffset = this->binary_->rva_to_offset(value);

      ExportEntry entry;
      try {
        entry.name_   = this->stream_->read_string(nameOffset);
      } catch (const LIEF::read_out_of_bound& e) {
        LOG(WARNING) << e.what();
      }

      entry.is_extern_ = true;
      entry.address_  = 0;
      entry.ordinal_  = i + exportDirectoryTable->OrdinalBase;
      exportObject.entries_.push_back(std::move(entry));

    }
  }

  // Parse export name table
  uint32_t offsetToNamePointer = this->binary_->rva_to_offset(exportDirectoryTable->NamePointerRVA);
  const uint32_t *pointerName  = reinterpret_cast<const uint32_t*>(
      this->stream_->read(offsetToNamePointer, nbof_name_ptr * sizeof(uint32_t)));

  for (size_t i = 0; i < nbof_name_ptr; ++i) {
    uint32_t nameOffset = this->binary_->rva_to_offset(pointerName[i]);
    std::string name  = "";
    try {
      name = this->stream_->read_string(nameOffset);
    } catch (const LIEF::read_out_of_bound& e) {
      LOG(WARNING) << e.what();
    }

    ExportEntry entry;
    entry.name_     = name;
    entry.is_extern_ = false;
    entry.ordinal_  = ordinalTable[i] + exportDirectoryTable->OrdinalBase;
    entry.address_  = addressTable[ordinalTable[i]];
    exportObject.entries_.push_back(std::move(entry));
  }

  this->binary_->export_ = std::move(exportObject);

}

void Parser::build_signature(void) {
  LOG(DEBUG) << "[+] Parsing signature";

  /*** /!\ In this data directory, RVA is used as an **OFFSET** /!\ ****/
  /*********************************************************************/
  const uint32_t signature_offset  = this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).RVA();
  const uint32_t signature_size = this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).size();
  LOG(DEBUG) << "Signature Offset: 0x" << std::hex << signature_offset;
  LOG(DEBUG) << "Signature Size: 0x" << std::hex << signature_size;

  //TODO: Deal with header (+8)
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
  LOG(DEBUG) << "OID (signedData): " << oid_str;
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

  LOG(DEBUG) << "Version: " << std::dec << version;
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

  LOG(DEBUG) << "digestAlgorithms: " << oid_str;

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
  LOG(DEBUG) << "contentType: " << oid_str;
  content_info.content_type_ = oid_str;
  p += content_type_oid.len;

  // content - SpcIndirectDataContent
  // |_ SpcAttributeTypeAndOptionalValue
  // |_ DigestInfo
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LOG(DEBUG) << "Parsing SpcIndirectDataContent (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
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
  LOG(DEBUG) << "Parsing SpcAttributeTypeAndOptionalValue (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
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
  LOG(DEBUG) << "SpcAttributeTypeAndOptionalValue->type " << oid_str;

  content_info.type_ = oid_str;
  p += content_type_oid.len;

  // SpcPeImageData
  // |_ SpcPeImageFlags
  // |_ SpcLink
  // ++++++++++++++
  LOG(DEBUG) << "Parsing SpcPeImageData (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    throw corrupted("Signature corrupted");
  }

  // SpcPeImageFlags
  // ^^^^^^^^^^^^^^^
  LOG(DEBUG) << "Parsing SpcPeImageFlags (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
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
  LOG(DEBUG) << "DigestInfo->digestAlgorithm: " << oid_str;

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
  LOG(DEBUG) << "Parsing Certificates (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }

  uint8_t* cert_end = p + tag;
  char buffer[1024];
  while (p < cert_end) {
    std::memset(buffer, 0, sizeof(buffer));

    mbedtls_x509_crt* ca = new mbedtls_x509_crt{};
    mbedtls_x509_crt_init(ca);
    mbedtls_x509_crt_parse_der(ca, p, end - p);

    signature.certificates_.emplace_back(ca);

    mbedtls_x509_crt_info(buffer, sizeof(buffer), "", ca);
    LOG(DEBUG) << std::endl << buffer << std::endl;

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

  LOG(DEBUG) << "Version: " << std::dec << version;
  LOG_IF(version != 1, WARNING) << "SignerInfo's version should be equal to 1 (" << std::dec << version << ")";
  signer_info.version_ = version;

  // issuerAndSerialNumber
  // ---------------------
  LOG(DEBUG) << "Parsing issuerAndSerialNumber (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";

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

    LOG(DEBUG) << "Component ID: " << oid_str;
    p += content_type_oid.len;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_PRINTABLE_STRING)) != 0) {
      throw corrupted("Signature corrupted");
    }

    std::string name{reinterpret_cast<char*>(p), tag};
    issuer_name.emplace_back(oid_str, name);
    LOG(DEBUG) << "Name: " << name;
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
  LOG(DEBUG) << "Parsing digestAlgorithm (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
  if ((ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid)) != 0) {
    throw corrupted("Signature corrupted");
  }

  std::memset(oid_str, 0, sizeof(oid_str));
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &alg_oid);
  LOG(DEBUG) << "signerInfo->digestAlgorithm " << oid_str;

  signer_info.digest_algorithm_ = oid_str;

  // authenticatedAttributes
  // |_ contentType
  // |_ messageDigest
  // |_ SpcSpOpusInfo
  // -----------------------
  AuthenticatedAttributes authenticated_attributes;

  LOG(DEBUG) << "Parsing authenticatedAttributes (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";
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

  LOG(DEBUG) << oid_str; // 1.2.840.113549.1.9.3 (PKCS #9 contentType)

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

  LOG(DEBUG) << oid_str; // 1.2.840.113549.1.9.4
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
  LOG(DEBUG) << "Parsing messageDigest (offset: " << std::dec << (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(signature_ptr)) << ")";

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
  LOG(DEBUG) << oid_str; // 1.2.840.113549.1.9.4
  p += content_type_oid.len;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)) != 0) {
    throw corrupted("Signature corrupted");
  }


  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
    throw corrupted("Signature corrupted");
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
  LOG(DEBUG) << oid_str; // 1.3.6.1.4.1.311.2.1.12 (SpcSpOpusInfoObjId)
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
  LOG(DEBUG) << "ProgName " << u16tou8(progname);
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
  LOG(DEBUG) << more_info;
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

  LOG(DEBUG) << "digestEncryptionAlgorithm: " << oid_str;

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
  LOG(DEBUG) << "Signature: " << std::endl << signature;
  this->binary_->signature_ = std::move(signature);
  this->binary_->has_signature_ = true;
}


void Parser::build_overlay(void) {
  LOG(DEBUG) << "Parsing Overlay";
  const uint64_t last_section_offset = std::accumulate(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_), 0,
      [] (uint64_t offset, const Section* section) {
        return std::max<uint64_t>(section->offset() + section->size(), offset);
      });

  LOG(DEBUG) << "Overlay offset: 0x" << std::hex << last_section_offset;

  if (last_section_offset < this->stream_->size()) {
    const uint64_t overlay_size = this->stream_->size() - last_section_offset;

    LOG(DEBUG) << "Overlay size: " << std::dec << overlay_size;

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
