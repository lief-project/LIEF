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
  if (std::is_same<PE_T, PE64>::value) {
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
void Builder::build_import_table(void) {
  using uint__ = typename PE_T::uint;

  // Compute size of the the diffrent (sub)sections
  // inside the future import section
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  // Size of pe_import + 1 for the null entry
  uint32_t import_table_size  = static_cast<uint32_t>((this->binary_->imports().size() + 1) * sizeof(pe_import)); // +1 for the null entry

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
  for (const Import& import : this->binary_->imports()) {
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
  size_t content_size_aligned = align(content.size(), this->binary_->optional_header().file_alignment());
  content.insert(std::end(content), content_size_aligned - content.size(), 0);

  // Create a new section to handle imports
  Section new_import_section{".l" + std::to_string(static_cast<uint32_t>(DATA_DIRECTORY::IMPORT_TABLE))};
  new_import_section.content(content);

  new_import_section.add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);

  auto&& it_import_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section) {
        return section != nullptr and section->is_type(PE_SECTION_TYPES::IMPORT);
      });

  // Remove 'import' type from the original section
  if (it_import_section != std::end(this->binary_->sections_)) {
    (*it_import_section)->remove_type(PE_SECTION_TYPES::IMPORT);
  }

  // As add_section will change DATA_DIRECTORY::IMPORT_TABLE we have to save it before
  uint32_t offset_imports  = this->binary_->rva_to_offset(this->binary_->data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA());
  Section& import_section = this->binary_->add_section(new_import_section, PE_SECTION_TYPES::IMPORT);


  // Patch the original IAT with the address of the associated trampoline
  if (this->patch_imports_) {
    Section& original_import = this->binary_->section_from_offset(offset_imports);
    std::vector<uint8_t> import_content  = original_import.content();
    uint32_t roffset_import = offset_imports - original_import.offset();

    pe_import *import_header = reinterpret_cast<pe_import*>(import_content.data() + roffset_import);
    uint32_t jumpOffsetTmp = trampolines_offset;
    while (import_header->ImportAddressTableRVA != 0) {
      uint32_t offsetTable = this->binary_->rva_to_offset(import_header->ImportLookupTableRVA)  - original_import.pointerto_raw_data();
      uint32_t offsetIAT   = this->binary_->rva_to_offset(import_header->ImportAddressTableRVA) - original_import.pointerto_raw_data();
      if (offsetTable > import_content.size() or offsetIAT > import_content.size()) {
        //TODO: Better handle
        LOG(ERROR) << "Can't patch" << std::endl;
        break;
      }
      uint__ *lookupTable = reinterpret_cast<uint__*>(import_content.data() + offsetTable);
      uint__ *IAT         = reinterpret_cast<uint__*>(import_content.data() + offsetIAT);

      while (*lookupTable != 0) {
        *IAT = static_cast<uint__>(this->binary_->optional_header().imagebase() + import_section.virtual_address() + jumpOffsetTmp);
        *lookupTable = *IAT;
        jumpOffsetTmp += trampoline_size;

        lookupTable++;
        IAT++;
      }
      import_header++;
    }
    original_import.content(import_content);
  }

  // Process libraries
  for (const Import& import : this->binary_->imports()) {
    // Header
    pe_import header;
    header.ImportLookupTableRVA  = static_cast<uint__>(import_section.virtual_address() + lookuptable_offset);
    header.TimeDateStamp         = static_cast<uint32_t>(import.timedatestamp());
    header.ForwarderChain        = static_cast<uint32_t>(import.forwarder_chain());
    header.NameRVA               = static_cast<uint__>(import_section.virtual_address() + libraries_name_offset);
    header.ImportAddressTableRVA = static_cast<uint__>(import_section.virtual_address() + iat_offset);

    // Copy the header in the "header section"
    std::copy(
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(pe_import),
        content.data() + import_table_offset);

    import_table_offset += sizeof(pe_import);

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
      if (this->patch_imports_) {
        std::vector<uint8_t> instructions;
        uint64_t address = this->binary_->optional_header().imagebase() + import_section.virtual_address() + iat_offset;
        if (this->binary_->hooks_.count(import_name) > 0 and this->binary_->hooks_[import_name].count(entry.name())) {
          address = this->binary_->hooks_[import_name][entry.name()];
          instructions = Builder::build_jmp_hook<PE_T>(this->binary_->optional_header().imagebase() + import_section.virtual_address() + trampolines_offset, address);
        } else {
          instructions = Builder::build_jmp<PE_T>(this->binary_->optional_header().imagebase() + import_section.virtual_address() + trampolines_offset, address);
        }
        std::copy(
            std::begin(instructions),
            std::end(instructions),
            content.data() + trampolines_offset);

        trampolines_offset += trampoline_size;
      }

      // Default: ordinal case
      uint__ lookup_table_value = entry.data();

      if (not entry.is_ordinal()) {

        lookup_table_value = import_section.virtual_address() + functions_name_offset;

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
        std::copy(
            std::begin(name),
            std::end(name),
            content.data() + functions_name_offset);

        functions_name_offset += name.size() + 1; // +1 for \0

        functions_name_offset += functions_name_offset % 2; //Require to be even
      }

      uint__ iat_value = 0;

      // Check if manually set
      if (entry.data() != entry.iat_value() and entry.iat_value() > 0) {
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
    std::fill(
      content.data() + lookuptable_offset,
      content.data() + lookuptable_offset + sizeof(uint__),
      0);

    std::fill(
      content.data() + iat_offset,
      content.data() + iat_offset + sizeof(uint__),
      0);

    lookuptable_offset  += sizeof(uint__);
    iat_offset += sizeof(uint__);

  }

  // Insert null entry at the end
  std::fill(
    content.data() + import_table_offset,
    content.data() + import_table_offset + sizeof(pe_import),
    0);

  import_table_offset += sizeof(pe_import);

  // Fill the section
  import_section.content(content);

  // Update IAT data directory
  const uint32_t rva = static_cast<uint32_t>(import_section.virtual_address() + iat_offset);
  this->binary_->data_directory(DATA_DIRECTORY::IAT).RVA(rva);
  this->binary_->data_directory(DATA_DIRECTORY::IAT).size(functions_name_offset - iat_offset + 1);
}

template<typename PE_T>
void Builder::build_optional_header(const OptionalHeader& optional_header) {
  using uint__             = typename PE_T::uint;
  using pe_optional_header = typename PE_T::pe_optional_header;

  // Build optional header
  this->binary_->optional_header().sizeof_image(static_cast<uint32_t>(this->binary_->virtual_size()));
  this->binary_->optional_header().sizeof_headers(static_cast<uint32_t>(this->binary_->sizeof_headers()));

  pe_optional_header optional_header_raw;
  optional_header_raw.Magic                   = static_cast<uint16_t>(optional_header.magic());
  optional_header_raw.MajorLinkerVersion      = static_cast<uint8_t> (optional_header.major_linker_version());
  optional_header_raw.MinorLinkerVersion      = static_cast<uint8_t> (optional_header.minor_linker_version());
  optional_header_raw.SizeOfCode              = static_cast<uint32_t>(optional_header.sizeof_code());
  optional_header_raw.SizeOfInitializedData   = static_cast<uint32_t>(optional_header.sizeof_initialized_data());
  optional_header_raw.SizeOfUninitializedData = static_cast<uint32_t>(optional_header.sizeof_uninitialized_data());
  optional_header_raw.AddressOfEntryPoint     = static_cast<uint32_t>(optional_header.addressof_entrypoint());
  optional_header_raw.BaseOfCode              = static_cast<uint32_t>(optional_header.baseof_code());

  if (std::is_same<PE_T, PE32>::value) {
    // Trick to avoid compilation error
    reinterpret_cast<pe32_optional_header*>(&optional_header_raw)->BaseOfData = static_cast<uint32_t>(optional_header.baseof_data());
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


  const uint32_t address_next_header = this->binary_->dos_header().addressof_new_exeheader() + sizeof(pe_header);
  this->ios_.seekp(address_next_header);
  this->ios_.write(reinterpret_cast<const uint8_t*>(&optional_header_raw), sizeof(pe_optional_header));

}


template<typename PE_T>
void Builder::build_tls(void) {
  using uint__ = typename PE_T::uint;
  using pe_tls = typename PE_T::pe_tls;

  auto&& it_tls = std::find_if(
    std::begin(this->binary_->sections_),
    std::end(this->binary_->sections_),
    [] (const Section* section)
    {
      const std::set<PE_SECTION_TYPES>& types = section->types();
      return types.size() == 1 and types.find(PE_SECTION_TYPES::TLS) != std::end(types);
    });

  Section *tls_section = nullptr;

  pe_tls tls_raw;
  const TLS& tls_obj = this->binary_->tls();

  // No .tls section register in the binary. We have to create it
  if (it_tls == std::end(this->binary_->sections_)) {
    Section new_section{".l" + std::to_string(static_cast<uint32_t>(DATA_DIRECTORY::TLS_TABLE))}; // .l9 -> lief.tls
    new_section.characteristics(0xC0300040);
    uint64_t tls_section_size = sizeof(pe_tls);

    const uint64_t offset_callbacks = this->binary_->va_to_offset(tls_obj.addressof_callbacks());
    const uint64_t offset_rawdata   = this->binary_->va_to_offset(tls_obj.addressof_raw_data().first);

    try {
      const Section& _ [[gnu::unused]] = this->binary_->section_from_offset(offset_callbacks);
    } catch (const not_found&) { // Callbacks will be in our section (not present yet)
      tls_section_size += tls_obj.callbacks().size() * sizeof(uint__);
    }


    try {
      const Section& _ [[gnu::unused]] = this->binary_->section_from_offset(offset_rawdata);
    } catch (const not_found&) { // data_template will be in our section (not present yet)
      tls_section_size += tls_obj.data_template().size();
    }

    tls_section_size = align(tls_section_size, this->binary_->optional_header().file_alignment());
    new_section.content(std::vector<uint8_t>(tls_section_size, 0));

    tls_section = &(this->binary_->add_section(new_section, PE_SECTION_TYPES::TLS));
  } else {
    tls_section = *it_tls;
  }

  tls_raw.RawDataStartVA    = static_cast<uint__>(tls_obj.addressof_raw_data().first);
  tls_raw.RawDataEndVA      = static_cast<uint__>(tls_obj.addressof_raw_data().second);
  tls_raw.AddressOfIndex    = static_cast<uint__>(tls_obj.addressof_index());
  tls_raw.AddressOfCallback = static_cast<uint__>(tls_obj.addressof_callbacks());
  tls_raw.SizeOfZeroFill    = static_cast<uint32_t>(tls_obj.sizeof_zero_fill());
  tls_raw.Characteristics   = static_cast<uint32_t>(tls_obj.characteristics());

  std::vector<uint8_t> data(sizeof(pe_tls), 0);

  std::copy(
      reinterpret_cast<uint8_t*>(&tls_raw),
      reinterpret_cast<uint8_t*>(&tls_raw) + sizeof(pe_tls),
      data.data());

  const uint64_t offset_callbacks = this->binary_->va_to_offset(tls_obj.addressof_callbacks());
  const uint64_t offset_rawdata   = this->binary_->va_to_offset(tls_obj.addressof_raw_data().first);
  try {
    Section& section_callbacks = this->binary_->section_from_offset(offset_callbacks);

    const uint64_t size_needed = (tls_obj.callbacks().size()) * sizeof(uint__);

    if (section_callbacks == *tls_section) {
      // Case where the section where callbacks are located is the same
      // than the current .tls section

      uint64_t relative_offset = offset_callbacks - tls_section->offset();

      for (uint__ callback : tls_obj.callbacks()) {
        data.insert(
            std::begin(data) + relative_offset,
            reinterpret_cast<uint8_t*>(&callback),
            reinterpret_cast<uint8_t*>(&callback) + sizeof(uint__));
        relative_offset += sizeof(uint__);
      }

      //data.insert(std::begin(data) + relative_offset + sizeof(uint__), sizeof(uint__), 0);

    } else {
      // Case where the section where callbacks are located is **not** in the same
      // current .tls section

      uint64_t relative_offset = offset_callbacks - section_callbacks.offset();
      std::vector<uint8_t> callback_data = section_callbacks.content();

      if (callback_data.size() < (relative_offset + size_needed)) {
        throw builder_error("Don't have enough space to write callbacks");
      }

      for (uint__ callback : tls_obj.callbacks()) {
        std::copy(
          reinterpret_cast<uint8_t*>(&callback),
          reinterpret_cast<uint8_t*>(&callback) + sizeof(uint__),
          callback_data.data() + relative_offset);
        relative_offset += sizeof(uint__);
      }
      section_callbacks.content(callback_data);

    }
  } catch (const not_found&) {
    throw builder_error("Can't find the section which holds callbacks.");
  }


  try {
    Section& section_rawdata = this->binary_->section_from_offset(offset_rawdata);

    const std::vector<uint8_t>& data_template = tls_obj.data_template();
    const uint64_t size_needed = data_template.size();

    if (section_rawdata == *tls_section) {
      // Case where the section where data templates are located in the same
      // than the current .tls section

      const uint64_t relative_offset = offset_rawdata - tls_section->offset();

      data.insert(
          std::begin(data) + relative_offset,
          std::begin(data_template),
          std::end(data_template));

    } else {
      const uint64_t relative_offset = offset_rawdata - section_rawdata.offset();
      std::vector<uint8_t> section_data = section_rawdata.content();
      const std::vector<uint8_t>& data_template = tls_obj.data_template();
      if (section_data.size() < (relative_offset + size_needed)) {
        throw builder_error("Don't have enough space to write data template.");
      }

      std::copy(
          std::begin(data_template),
          std::end(data_template),
          section_data.data() + relative_offset);
      section_rawdata.content(section_data);

    }
  } catch (const not_found&) {
    throw builder_error("Can't find the section which holds 'data_template'.");
  }


  if (data.size() > tls_section->size()) {
    throw builder_error("Builder constructed a bigger section that the original one.");
  }

  data.insert(std::end(data), tls_section->size() - data.size(), 0);
  tls_section->content(data);

}

}
}
