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

#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/TLS.hpp"
#include "PE/Structures.hpp"

#include "logging.hpp"

namespace LIEF {
namespace PE {

template<typename PE_T>
std::vector<uint8_t> Builder::build_jmp(uint64_t from, uint64_t address) {
  std::vector<uint8_t> instruction;

  // call $+5
  instruction.push_back(0xe8);
  instruction.push_back(0x00);
  instruction.push_back(0x00);
  instruction.push_back(0x00);
  instruction.push_back(0x00);

  // pop eax/pop rax
  instruction.push_back(0x58); // eax/rax holds the current PC

  // add rax/eax (signed)
  if (std::is_same<PE_T, details::PE64>::value) {
    instruction.push_back(0x48); //x64
  }
  instruction.push_back(0x05);

  uint64_t diff = address - (from + 5);

  for (size_t i = 0; i < sizeof(uint32_t); ++i) {
    instruction.push_back(static_cast<uint8_t>((diff >> (8 * i)) & 0xFF));
  }
  // jmp [rax/eax]
  instruction.push_back(0xff);
  instruction.push_back(0x20);

  return instruction;
}


template<typename PE_T>
std::vector<uint8_t> Builder::build_jmp_hook(uint64_t from, uint64_t address) {
  std::vector<uint8_t> instruction;
  instruction.push_back(0xe9); // jmp xxxx
  uint64_t disp = address - from - 5;

  for (size_t i = 0; i < sizeof(uint32_t); ++i) {
    instruction.push_back(static_cast<uint8_t>((disp >> (8 * i)) & 0xFF));
  }

  return instruction;
}


/*
         Original IAT                        New IAT
     +------------------+             +------------------+
     |Trampoline 1 addr |------+      |   new address 1  |-+
     +------------------+      |      +------------------+ |
     |Trampoline 2 addr |      |      |   new address 1  | |
     +------------------+      |      +------------------+ |
     |Trampoline 3 addr |      |      |   new address 1  | |
     +------------------+      |      +------------------+ |
                               |                           |
                               |        Trampoline 1    +--+
                               |      +-----------------v-----+             Kernel32.dll
                               +----->|  mov rax, [new addr1] |           +--------------+
                                      |  jmp rax              |---------->| GetLocalTime |
                                      +-----------------------+           +--------------+
                                                                     +--->|  LocalSize   |
                                        Trampoline 2                 |    +--------------+
                                      +-----------------------+      |    |  WriteFile   |
                                      |  mov rax, [new addr2] |      |    +--------------+
                                      |  jmp rax              |------+
                                      +-----------------------+

*/

template<typename PE_T>
void Builder::build_import_table() {
  using uint__ = typename PE_T::uint;

  // Compute size of the the diffrent (sub)sections
  // inside the future import section
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  // Size of pe_import + 1 for the null entry
  uint32_t import_table_size  = static_cast<uint32_t>((binary_->imports().size() + 1) * sizeof(details::pe_import)); // +1 for the null entry

  // Size of import entries
  uint32_t entries_size = 0;

  // Size of the section which will holds imported functions names
  uint32_t functions_name_size = 0;

  // Size of the section which will holds library name (e.g. kernel32.dll)
  uint32_t libraries_name_size = 0;

  // Size of the trampoline section
  uint32_t trampolines_size = 0;

  // Size of the instructions in the trampoline
  uint32_t trampoline_size = build_jmp<PE_T>(0, 0).size();

  // Compute size of each imports's sections
  for (const Import& import : binary_->imports()) {
    for (const ImportEntry& entry : import.entries()) {

      functions_name_size += 2 + entry.name().size() + 1; // [Hint] [Name\0]
      functions_name_size += functions_name_size % 2;     // [padding]
    }

    libraries_name_size  += import.name().size() + 1; // [Name\0]
    entries_size += 2 * (import.entries().size() + 1) * sizeof(uint__); // Once for Lookup table and the other for Import Address Table (IAT). +1 for the null entry
    trampolines_size    += import.entries().size() * trampoline_size;
  }

  // Offset of the diffrents sections inside *import section*
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  // Offset to the import table (i.e list of pe_import)
  uint32_t import_table_offset = 0;

  // Offset to the lookup table: After import table
  uint32_t lookuptable_offset = import_table_offset + import_table_size;

  // Address table (IAT). Identical to the lookup table until the library is bound
  uint32_t iat_offset = lookuptable_offset + entries_size / 2;

  // Offset to the section which will contains hints/names of the imported functions name
  uint32_t functions_name_offset = iat_offset + entries_size / 2;

  // Offset of the section which will holds libraries name
  uint32_t libraries_name_offset = functions_name_offset + functions_name_size;

  // Offset of the section where trampolines will be written
  uint32_t trampolines_offset = libraries_name_offset + libraries_name_size;

  // Create empty content of the required size and align it
  std::vector<uint8_t> content(trampolines_offset + trampolines_size, 0);
  size_t content_size_aligned = align(content.size(), binary_->optional_header().file_alignment());
  content.insert(std::end(content), content_size_aligned - content.size(), 0);

  // Create a new section to handle imports
  Section new_import_section{".l" + std::to_string(static_cast<uint32_t>(DataDirectory::TYPES::IMPORT_TABLE))};
  new_import_section.content(content);

  new_import_section.add_characteristic(Section::CHARACTERISTICS::CNT_CODE);

  const auto it_import_section = std::find_if(std::begin(binary_->sections_), std::end(binary_->sections_),
      [] (const std::unique_ptr<Section>& section) {
        return section != nullptr && section->is_type(PE_SECTION_TYPES::IMPORT);
      });

  // Remove 'import' type from the original section
  if (it_import_section != std::end(binary_->sections_)) {
    (*it_import_section)->remove_type(PE_SECTION_TYPES::IMPORT);
  }

  // As add_section will change DataDirectory::TYPES::IMPORT_TABLE we have to save it before
  uint32_t offset_imports  = binary_->rva_to_offset(binary_->data_directory(DataDirectory::TYPES::IMPORT_TABLE)->RVA());
  Section* import_section = binary_->add_section(new_import_section, PE_SECTION_TYPES::IMPORT);
  if (import_section == nullptr) {
    return;
  }


  // Patch the original IAT with the address of the associated trampoline
  if (patch_imports_) {
    Section* original_import = binary_->section_from_offset(offset_imports);
    if (original_import == nullptr) {
      LIEF_ERR("Can't find the section associated with the import table");
      return;
    }
    span<uint8_t> import_content  = original_import->writable_content();
    uint32_t roffset_import = offset_imports - original_import->offset();

    auto* import_header = reinterpret_cast<details::pe_import*>(import_content.data() + roffset_import);
    uint32_t jumpOffsetTmp = trampolines_offset;
    while (import_header->ImportAddressTableRVA != 0) {
      uint32_t offsetTable = binary_->rva_to_offset(import_header->ImportLookupTableRVA)  - original_import->pointerto_raw_data();
      uint32_t offsetIAT   = binary_->rva_to_offset(import_header->ImportAddressTableRVA) - original_import->pointerto_raw_data();
      if (offsetTable > import_content.size() || offsetIAT > import_content.size()) {
        //TODO: Better handle
        LIEF_ERR("Can't patch");
        break;
      }
      auto *lookupTable = reinterpret_cast<uint__*>(import_content.data() + offsetTable);
      auto *IAT         = reinterpret_cast<uint__*>(import_content.data() + offsetIAT);

      while (*lookupTable != 0) {
        *IAT = static_cast<uint__>(binary_->optional_header().imagebase() + import_section->virtual_address() + jumpOffsetTmp);
        *lookupTable = *IAT;
        jumpOffsetTmp += trampoline_size;

        lookupTable++;
        IAT++;
      }
      import_header++;
    }
  }

  // Process libraries
  for (const Import& import : binary_->imports()) {
    // Header
    details::pe_import header;
    header.ImportLookupTableRVA  = static_cast<uint__>(import_section->virtual_address() + lookuptable_offset);
    header.TimeDateStamp         = static_cast<uint32_t>(import.timedatestamp());
    header.ForwarderChain        = static_cast<uint32_t>(import.forwarder_chain());
    header.NameRVA               = static_cast<uint__>(import_section->virtual_address() + libraries_name_offset);
    header.ImportAddressTableRVA = static_cast<uint__>(import_section->virtual_address() + iat_offset);

    // Copy the header in the "header section"
    std::copy(
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(details::pe_import),
        content.data() + import_table_offset);

    import_table_offset += sizeof(details::pe_import);

    // Copy the name in the "string section"
    const std::string& import_name = import.name();
    std::copy(
        std::begin(import_name),
        std::end(import_name),
        content.data() + libraries_name_offset);

    libraries_name_offset += import_name.size() + 1; // +1 for '\0'

    // Process imported functions
    for (const ImportEntry& entry : import.entries()) {

      // If patch is enabled, we have to create a trampoline for this function
      if (patch_imports_) {
        std::vector<uint8_t> instructions;
        uint64_t address = binary_->optional_header().imagebase() + import_section->virtual_address() + iat_offset;
        instructions = Builder::build_jmp<PE_T>(binary_->optional_header().imagebase() + import_section->virtual_address() + trampolines_offset, address);
        std::copy(
            std::begin(instructions),
            std::end(instructions),
            content.data() + trampolines_offset);

        trampolines_offset += trampoline_size;
      }

      // Default: ordinal case
      uint__ lookup_table_value = entry.data();

      if (!entry.is_ordinal()) {

        lookup_table_value = import_section->virtual_address() + functions_name_offset;

        // Insert entry in hint/name table
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // First: hint
        const uint16_t hint = entry.hint();
        std::copy(
            reinterpret_cast<const uint8_t*>(&hint),
            reinterpret_cast<const uint8_t*>(&hint) + sizeof(uint16_t),
            content.data() + functions_name_offset); //hintIdx

        functions_name_offset += sizeof(uint16_t);

        // Then: name
        const std::string& name = entry.name();
        std::copy(std::begin(name), std::end(name),
                  content.data() + functions_name_offset);

        functions_name_offset += name.size() + 1; // +1 for \0

        functions_name_offset += functions_name_offset % 2; //Require to be even
      }

      uint__ iat_value = 0;

      // Check if manually set
      if (entry.data() != entry.iat_value() && entry.iat_value() > 0) {
        iat_value = entry.iat_value();
      } else { // default value same that in the lookup table
        iat_value = lookup_table_value;
      }

      // Insert entry in lookup table and address table
      std::copy(
        reinterpret_cast<const uint8_t*>(&lookup_table_value),
        reinterpret_cast<const uint8_t*>(&lookup_table_value) + sizeof(uint__),
        content.data() + lookuptable_offset);

      std::copy(
        reinterpret_cast<const uint8_t*>(&iat_value),
        reinterpret_cast<const uint8_t*>(&iat_value) + sizeof(uint__),
        content.data() + iat_offset);

      lookuptable_offset += sizeof(uint__);
      iat_offset += sizeof(uint__);

    }

    // Insert null entry at the end
    std::fill(content.data() + lookuptable_offset,
              content.data() + lookuptable_offset + sizeof(uint__), 0);

    std::fill(content.data() + iat_offset,
              content.data() + iat_offset + sizeof(uint__), 0);

    lookuptable_offset  += sizeof(uint__);
    iat_offset += sizeof(uint__);

  }

  // Insert null entry at the end
  std::memset(content.data() + import_table_offset, 0, sizeof(details::pe_import));

  import_table_offset += sizeof(details::pe_import);

  // Fill the section
  import_section->content(content);

  // Update IAT data directory
  const auto rva = static_cast<uint32_t>(import_section->virtual_address() + iat_offset);
  binary_->data_directory(DataDirectory::TYPES::IAT)->RVA(rva);
  binary_->data_directory(DataDirectory::TYPES::IAT)->size(functions_name_offset - iat_offset + 1);
}

template<typename PE_T>
ok_error_t Builder::build_optional_header(const OptionalHeader& optional_header) {
  using uint__             = typename PE_T::uint;
  using pe_optional_header = typename PE_T::pe_optional_header;

  // Build optional header
  binary_->optional_header().sizeof_image(static_cast<uint32_t>(binary_->virtual_size()));
  binary_->optional_header().sizeof_headers(static_cast<uint32_t>(binary_->sizeof_headers()));

  pe_optional_header optional_header_raw;
  optional_header_raw.Magic                   = static_cast<uint16_t>(optional_header.magic());
  optional_header_raw.MajorLinkerVersion      = static_cast<uint8_t> (optional_header.major_linker_version());
  optional_header_raw.MinorLinkerVersion      = static_cast<uint8_t> (optional_header.minor_linker_version());
  optional_header_raw.SizeOfCode              = static_cast<uint32_t>(optional_header.sizeof_code());
  optional_header_raw.SizeOfInitializedData   = static_cast<uint32_t>(optional_header.sizeof_initialized_data());
  optional_header_raw.SizeOfUninitializedData = static_cast<uint32_t>(optional_header.sizeof_uninitialized_data());
  optional_header_raw.AddressOfEntryPoint     = static_cast<uint32_t>(optional_header.addressof_entrypoint());
  optional_header_raw.BaseOfCode              = static_cast<uint32_t>(optional_header.baseof_code());

  if (std::is_same<PE_T, details::PE32>::value) {
    reinterpret_cast<details::pe32_optional_header*>(&optional_header_raw)->BaseOfData = static_cast<uint32_t>(optional_header.baseof_data());
  }
  optional_header_raw.ImageBase                    = static_cast<uint__>(optional_header.imagebase());
  optional_header_raw.SectionAlignment             = static_cast<uint32_t>(optional_header.section_alignment());
  optional_header_raw.FileAlignment                = static_cast<uint32_t>(optional_header.file_alignment());
  optional_header_raw.MajorOperatingSystemVersion  = static_cast<uint16_t>(optional_header.major_operating_system_version());
  optional_header_raw.MinorOperatingSystemVersion  = static_cast<uint16_t>(optional_header.minor_operating_system_version());
  optional_header_raw.MajorImageVersion            = static_cast<uint16_t>(optional_header.major_image_version());
  optional_header_raw.MinorImageVersion            = static_cast<uint16_t>(optional_header.minor_image_version());
  optional_header_raw.MajorSubsystemVersion        = static_cast<uint16_t>(optional_header.major_subsystem_version());
  optional_header_raw.MinorSubsystemVersion        = static_cast<uint16_t>(optional_header.minor_subsystem_version());
  optional_header_raw.Win32VersionValue            = static_cast<uint16_t>(optional_header.win32_version_value());
  optional_header_raw.SizeOfImage                  = static_cast<uint32_t>(optional_header.sizeof_image());
  optional_header_raw.SizeOfHeaders                = static_cast<uint32_t>(optional_header.sizeof_headers());
  optional_header_raw.CheckSum                     = static_cast<uint32_t>(optional_header.checksum());
  optional_header_raw.Subsystem                    = static_cast<uint16_t>(optional_header.subsystem());
  optional_header_raw.DLLCharacteristics           = static_cast<uint16_t>(optional_header.dll_characteristics());
  optional_header_raw.SizeOfStackReserve           = static_cast<uint__>(optional_header.sizeof_stack_reserve());
  optional_header_raw.SizeOfStackCommit            = static_cast<uint__>(optional_header.sizeof_stack_commit());
  optional_header_raw.SizeOfHeapReserve            = static_cast<uint__>(optional_header.sizeof_heap_reserve());
  optional_header_raw.SizeOfHeapCommit             = static_cast<uint__>(optional_header.sizeof_heap_commit());
  optional_header_raw.LoaderFlags                  = static_cast<uint32_t>(optional_header.loader_flags());
  optional_header_raw.NumberOfRvaAndSize           = static_cast<uint32_t>(optional_header.numberof_rva_and_size());


  const uint32_t address_next_header = binary_->dos_header().addressof_new_exeheader() + sizeof(details::pe_header);
  ios_.seekp(address_next_header);
  ios_.write(reinterpret_cast<const uint8_t*>(&optional_header_raw), sizeof(pe_optional_header));
  return ok();
}


template<typename PE_T>
ok_error_t Builder::build_tls() {
  using uint__ = typename PE_T::uint;
  using pe_tls = typename PE_T::pe_tls;

  const auto it_tls = std::find_if(std::begin(binary_->sections_), std::end(binary_->sections_),
    [] (const std::unique_ptr<Section>& section) {
      const std::set<PE_SECTION_TYPES>& types = section->types();
      return types.size() == 1 && types.find(PE_SECTION_TYPES::TLS) != std::end(types);
    });

  Section *tls_section = nullptr;

  pe_tls tls_raw;
  const TLS* tls_obj = binary_->tls();

  // No .tls section register in the binary. We have to create it
  if (it_tls == std::end(binary_->sections_)) {
    Section new_section{".l" + std::to_string(static_cast<uint32_t>(DataDirectory::TYPES::TLS_TABLE))}; // .l9 -> lief.tls
    new_section.characteristics(0xC0300040);
    uint64_t tls_section_size = sizeof(pe_tls);

    const uint64_t offset_callbacks = binary_->va_to_offset(tls_obj->addressof_callbacks());
    const uint64_t offset_rawdata   = binary_->va_to_offset(tls_obj->addressof_raw_data().first);

    Section* callbacks_sec = binary_->section_from_offset(offset_callbacks);
    if (callbacks_sec == nullptr) {
      tls_section_size += tls_obj->callbacks().size() * sizeof(uint__);
    }

    Section* data_sec = binary_->section_from_offset(offset_rawdata);
    if (data_sec == nullptr) {
      tls_section_size += tls_obj->data_template().size();
    }

    tls_section_size = align(tls_section_size, binary_->optional_header().file_alignment());
    new_section.content(std::vector<uint8_t>(tls_section_size, 0));

    tls_section = binary_->add_section(new_section, PE_SECTION_TYPES::TLS);
    if (tls_section == nullptr) {
      return make_error_code(lief_errors::build_error);
    }

  } else {
    tls_section = it_tls->get();
  }

  tls_raw.RawDataStartVA    = static_cast<uint__>(tls_obj->addressof_raw_data().first);
  tls_raw.RawDataEndVA      = static_cast<uint__>(tls_obj->addressof_raw_data().second);
  tls_raw.AddressOfIndex    = static_cast<uint__>(tls_obj->addressof_index());
  tls_raw.AddressOfCallback = static_cast<uint__>(tls_obj->addressof_callbacks());
  tls_raw.SizeOfZeroFill    = static_cast<uint32_t>(tls_obj->sizeof_zero_fill());
  tls_raw.Characteristics   = static_cast<uint32_t>(tls_obj->characteristics());

  std::vector<uint8_t> data(sizeof(pe_tls), 0);

  std::copy(
      reinterpret_cast<uint8_t*>(&tls_raw), reinterpret_cast<uint8_t*>(&tls_raw) + sizeof(pe_tls),
      data.data());

  const uint64_t offset_callbacks = binary_->va_to_offset(tls_obj->addressof_callbacks());
  const uint64_t offset_rawdata   = binary_->va_to_offset(tls_obj->addressof_raw_data().first);
  Section* section_callbacks = binary_->section_from_offset(offset_callbacks);
  if (section_callbacks == nullptr) {
    LIEF_ERR("Can't find the section which holds callbacks.");
    return make_error_code(lief_errors::not_found);
  }

  const uint64_t size_needed = (tls_obj->callbacks().size()) * sizeof(uint__);

  if (section_callbacks == tls_section) {
    // Case where the section where callbacks are located is the same
    // than the current .tls section

    uint64_t relative_offset = offset_callbacks - tls_section->offset();

    for (uint__ callback : tls_obj->callbacks()) {
      data.insert(std::begin(data) + relative_offset,
                  reinterpret_cast<uint8_t*>(&callback),
                  reinterpret_cast<uint8_t*>(&callback) + sizeof(uint__));
      relative_offset += sizeof(uint__);
    }

    //data.insert(std::begin(data) + relative_offset + sizeof(uint__), sizeof(uint__), 0);

  } else {
    // Case where the section where callbacks are located is **not** in the same
    // current .tls section

    uint64_t relative_offset = offset_callbacks - section_callbacks->offset();
    span<uint8_t> callback_data = section_callbacks->writable_content();

    if ((relative_offset + size_needed) > callback_data.size()) {
      LIEF_ERR("Don't have enough space to write callbacks");
      return make_error_code(lief_errors::build_error);
    }

    for (uint__ callback : tls_obj->callbacks()) {
      memcpy(callback_data.data() + relative_offset, &callback, sizeof(uint__));
      relative_offset += sizeof(uint__);
    }
  }



  Section* section_rawdata = binary_->section_from_offset(offset_rawdata);
  if (section_rawdata == nullptr) {
    LIEF_ERR("Can't find the section which holds 'data_template'.");
    return make_error_code(lief_errors::not_found);
  }
  {
    span<const uint8_t> data_template = tls_obj->data_template();
    const uint64_t size_needed = data_template.size();

    if (section_rawdata == tls_section) {
      // Case where the section where data templates are located in the same
      // than the current .tls section
      const uint64_t relative_offset = offset_rawdata - tls_section->offset();

      data.insert(std::begin(data) + relative_offset, std::begin(data_template),
                  std::end(data_template));
    } else {
      const uint64_t relative_offset = offset_rawdata - section_rawdata->offset();
      span<uint8_t> section_data = section_rawdata->writable_content();
      span<const uint8_t> data_template = tls_obj->data_template();
      if ((relative_offset + size_needed) > section_data.size()) {
        return make_error_code(lief_errors::build_error);
      }

      std::copy(std::begin(data_template), std::end(data_template),
                section_data.data() + relative_offset);
    }
  }

  if (data.size() > tls_section->size()) {
    LIEF_ERR("The builder constructed a larger section that the original one.");
    return make_error_code(lief_errors::build_error);
  }

  data.insert(std::end(data), tls_section->size() - data.size(), 0);
  tls_section->content(data);
  return ok();
}

}
}
