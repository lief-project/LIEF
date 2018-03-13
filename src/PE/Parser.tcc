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
#include "LIEF/logging++.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

#include "LoadConfigurations/LoadConfigurations.tcc"

namespace LIEF {
namespace PE {

template<typename PE_T>
void Parser::parse(void) {

  try {
    this->parse_headers<PE_T>();
  } catch (const corrupted& e) {
    LOG(WARNING) << e.what();
  }

  VLOG(VDEBUG) << "[+] Retreive Dos stub";

  this->parse_dos_stub();

  try {
    this->parse_rich_header();
  } catch (const corrupted& e) {
    LOG(WARNING) << e.what();
  }

  VLOG(VDEBUG) << "[+] Decomposing Sections";

  try {
    this->parse_sections();
  } catch (const corrupted& e) {
    LOG(WARNING) << e.what();
  }

  VLOG(VDEBUG) << "[+] Decomposing Data directories";
  try {
    this->parse_data_directories<PE_T>();
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  try {
    this->parse_symbols();
  } catch (const corrupted& e) {
    LOG(WARNING) << e.what();
  }

  this->parse_overlay();
}

template<typename PE_T>
void Parser::parse_headers(void) {
  using pe_optional_header = typename PE_T::pe_optional_header;

  //DOS Header
  try {
    this->binary_->dos_header_ = {reinterpret_cast<const pe_dos_header*>(
        this->stream_->read(0, sizeof(pe_dos_header)))};

  } catch (const read_out_of_bound&) {
    throw corrupted("Dos Header corrupted");
  }


  //PE32 Header
  try {
    this->binary_->header_ = {reinterpret_cast<const pe_header*>(
      this->stream_->read(
        this->binary_->dos_header().addressof_new_exeheader(),
        sizeof(pe_header)))};
  } catch (const read_out_of_bound&) {
    throw corrupted("PE32 Header corrupted");
  }

  // Optional Header
  try {
    this->binary_->optional_header_ = {reinterpret_cast<const pe_optional_header*>(
        this->stream_->read(
          this->binary_->dos_header().addressof_new_exeheader() + sizeof(pe_header),
          sizeof(pe_optional_header)))};
  } catch (const read_out_of_bound&) {
    throw corrupted("Optional header corrupted");
  }
}

template<typename PE_T>
void Parser::parse_data_directories(void) {
  using pe_optional_header = typename PE_T::pe_optional_header;

  VLOG(VDEBUG) << "[+] Parsing data directories";

  const uint32_t dirOffset =
      this->binary_->dos_header().addressof_new_exeheader() +
      sizeof(pe_header) +
      sizeof(pe_optional_header);
  const uint32_t nbof_datadir = static_cast<uint32_t>(DATA_DIRECTORY::NUM_DATA_DIRECTORIES);

  const pe_data_directory* dataDirectory = [&] () {
    try {
      return reinterpret_cast<const pe_data_directory*>(
        this->stream_->read(dirOffset, nbof_datadir * sizeof(pe_data_directory)));
    } catch (const read_out_of_bound&) {
      throw corrupted("Data directories corrupted");
    }
  }();

  this->binary_->data_directories_.reserve(nbof_datadir);
  for (size_t i = 0; i < nbof_datadir; ++i) {
    std::unique_ptr<DataDirectory> directory{new DataDirectory{&dataDirectory[i], static_cast<DATA_DIRECTORY>(i)}};

    VLOG(VDEBUG) << "Processing directory: " << to_string(static_cast<DATA_DIRECTORY>(i));
    VLOG(VDEBUG) << "- RVA: 0x" << std::hex << dataDirectory[i].RelativeVirtualAddress;
    VLOG(VDEBUG) << "- Size: 0x" << std::hex << dataDirectory[i].Size;
    if (directory->RVA() > 0) {
      // Data directory is not always associated with section
      const uint64_t offset = this->binary_->rva_to_offset(directory->RVA());
      try {
        directory->section_ = &(this->binary_->section_from_offset(offset));
      } catch (const LIEF::not_found&) {
          LOG(WARNING) << "Unable to find the section associated with "
                       << to_string(static_cast<DATA_DIRECTORY>(i));
      }
    }
    this->binary_->data_directories_.push_back(directory.release());
  }

  try {
    // Import Table
    if (this->binary_->data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA() > 0) {
      VLOG(VDEBUG) << "[+] Decomposing Import Table";
      const uint32_t import_rva = this->binary_->data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA();
      const uint64_t offset     = this->binary_->rva_to_offset(import_rva);

      try {
        Section& section = this->binary_->section_from_offset(offset);
        section.add_type(PE_SECTION_TYPES::IMPORT);
      } catch (const not_found&) {
        LOG(WARNING) << "Unable to find the section associated with Import Table";
      }
      this->parse_import_table<PE_T>();
    }
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  // Exports
  if (this->binary_->data_directory(DATA_DIRECTORY::EXPORT_TABLE).RVA() > 0) {
    VLOG(VDEBUG) << "[+] Decomposing Exports";

    try {
      this->parse_exports();
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }

  // Signature
  if (this->binary_->data_directory(DATA_DIRECTORY::CERTIFICATE_TABLE).RVA() > 0) {
    try {
      this->parse_signature();
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }


  // TLS
  if (this->binary_->data_directory(DATA_DIRECTORY::TLS_TABLE).RVA() > 0) {
    VLOG(VDEBUG) << "[+] Decomposing TLS";

    const uint32_t tls_rva = this->binary_->data_directory(DATA_DIRECTORY::TLS_TABLE).RVA();
    const uint64_t offset  = this->binary_->rva_to_offset(tls_rva);
    try {
      Section& section = this->binary_->section_from_offset(offset);
      section.add_type(PE_SECTION_TYPES::TLS);
      this->parse_tls<PE_T>();
    } catch (const not_found&) {
      LOG(WARNING) << "Unable to find the section associated with TLS";
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }

  // Load Config
  if (this->binary_->data_directory(DATA_DIRECTORY::LOAD_CONFIG_TABLE).RVA() > 0) {

    const uint32_t load_config_rva = this->binary_->data_directory(DATA_DIRECTORY::LOAD_CONFIG_TABLE).RVA();
    const uint64_t offset          = this->binary_->rva_to_offset(load_config_rva);
    try {
      Section& section = this->binary_->section_from_offset(offset);
      section.add_type(PE_SECTION_TYPES::LOAD_CONFIG);
      this->parse_load_config<PE_T>();
    } catch (const not_found&) {
      LOG(WARNING) << "Unable to find the section associated with Load Config";
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }


  // Relocations
  if (this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA() > 0) {

    VLOG(VDEBUG) << "[+] Decomposing relocations";
    const uint32_t relocation_rva = this->binary_->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA();
    const uint64_t offset         = this->binary_->rva_to_offset(relocation_rva);
    try {
      Section& section = this->binary_->section_from_offset(offset);
      section.add_type(PE_SECTION_TYPES::RELOCATION);
      this->parse_relocations();
    } catch (const not_found&) {
      LOG(WARNING) << "Unable to find the section associated with relocations";
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }


  // Debug
  if (this->binary_->data_directory(DATA_DIRECTORY::DEBUG).RVA() > 0) {

    VLOG(VDEBUG) << "[+] Decomposing debug";
    const uint32_t rva    = this->binary_->data_directory(DATA_DIRECTORY::DEBUG).RVA();
    const uint64_t offset = this->binary_->rva_to_offset(rva);
    try {
      Section& section = this->binary_->section_from_offset(offset);
      section.add_type(PE_SECTION_TYPES::DEBUG);
      this->parse_debug();
    } catch (const not_found&) {
      LOG(WARNING) << "Unable to find the section associated with debug";
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }
  }


  // Resources
  if (this->binary_->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA() > 0) {

    VLOG(VDEBUG) << "[+] Decomposing resources";
    const uint32_t resources_rva = this->binary_->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA();
    const uint64_t offset        = this->binary_->rva_to_offset(resources_rva);
    try {
      Section& section  = this->binary_->section_from_offset(offset);
      section.add_type(PE_SECTION_TYPES::RESOURCE);
      this->parse_resources();
    } catch (const not_found&) {
      LOG(WARNING) << "Unable to find the section associated with resources";
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }

  }
}

template<typename PE_T>
void Parser::parse_import_table(void) {
  using uint__ = typename PE_T::uint;

  this->binary_->has_imports_ = true;

  const uint32_t import_rva = this->binary_->data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA();
  const uint64_t offset     = this->binary_->rva_to_offset(import_rva);

  const pe_import* header = reinterpret_cast<const pe_import*>(
    this->stream_->read(offset, sizeof(pe_import)));

  while (header->ImportAddressTableRVA != 0) {
    Import import           = {header};
    import.directory_       = &(this->binary_->data_directory(DATA_DIRECTORY::IMPORT_TABLE));
    import.iat_directory_   = &(this->binary_->data_directory(DATA_DIRECTORY::IAT));
    import.type_            = this->type_;
    if (import.name_RVA_ == 0) {
      throw parser_error("Name's RVA is null");
    }
    // Offset to the Import (Library) name
    const uint64_t offsetName = this->binary_->rva_to_offset(import.name_RVA_);
    import.name_              = this->stream_->get_string(offsetName);


    // We assume that a DLL name should be at least 4 length size and "printable
    if (import.name().size() < MIN_DLL_NAME_SIZE or not
        std::all_of(
          std::begin(import.name()),
          std::end(import.name()),
          std::bind(std::isprint<char>, std::placeholders::_1, std::locale("C"))))
    {
      header++;
      continue; // skip
    }

    // Offset to import lookup table
    uint64_t LT_offset      = 0;
    if (import.import_lookup_table_RVA_ > 0) {
      LT_offset = this->binary_->rva_to_offset(import.import_lookup_table_RVA_);
    }

    // Offset to the import address table
    uint64_t IAT_offset        = 0;
    if (import.import_address_table_RVA_ > 0) {
      IAT_offset = this->binary_->rva_to_offset(import.import_address_table_RVA_);
    }

    const uint__ *lookupTable = nullptr, *IAT = nullptr, *table = nullptr;

    if (IAT_offset > 0) {
      try {
        IAT = reinterpret_cast<const uint__*>(
            this->stream_->read(IAT_offset, sizeof(uint__)));
        table = IAT;
      } catch (const LIEF::exception&) {
      }
    }

    if (LT_offset > 0) {
      try {
        lookupTable = reinterpret_cast<const uint__*>(
            this->stream_->read(LT_offset, sizeof(uint__)));

        table = lookupTable;
      } catch (const LIEF::exception&) {
      }

    }

    size_t idx = 0;
    while (table != nullptr and *table != 0) {
      ImportEntry entry;
      entry.iat_value_ = IAT != nullptr ? *(IAT++) : 0;
      entry.data_      = *table;
      entry.type_      = this->type_;
      entry.rva_       = import.import_address_table_RVA_ + sizeof(uint__) * (idx++);

      if(not entry.is_ordinal()) {

        entry.name_ = this->stream_->get_string(
            this->binary_->rva_to_offset(entry.hint_name_rva()) + sizeof(uint16_t));

        entry.hint_ = *reinterpret_cast<const uint16_t*>(
            this->stream_->read(
              this->binary_->rva_to_offset(entry.hint_name_rva()),
              sizeof(uint16_t)));
      }

      import.entries_.push_back(std::move(entry));

      table++;
    }
    this->binary_->imports_.push_back(std::move(import));
    header++;
  }

}

template<typename PE_T>
void Parser::parse_tls(void) {
  using pe_tls = typename PE_T::pe_tls;
  using uint__ = typename PE_T::uint;

  VLOG(VDEBUG) << "[+] Parsing TLS";

  this->binary_->has_tls_ = true;

  const uint32_t tls_rva = this->binary_->data_directory(DATA_DIRECTORY::TLS_TABLE).RVA();
  const uint64_t offset  = this->binary_->rva_to_offset(tls_rva);

  const pe_tls *tls_header = reinterpret_cast<const pe_tls*>(
      this->stream_->read(offset, sizeof(pe_tls)));

  this->binary_->tls_ = {tls_header};
  TLS& tls = this->binary_->tls_;

  const uint64_t imagebase = this->binary_->optional_header().imagebase();


  if (tls_header->RawDataStartVA > 0 and tls_header->RawDataEndVA > tls_header->RawDataStartVA) {
    const uint64_t start_data_rva = tls_header->RawDataStartVA - imagebase;
    const uint64_t stop_data_rva  = tls_header->RawDataEndVA - imagebase;

    const uint__ start_template_offset  = this->binary_->rva_to_offset(start_data_rva);
    const uint__ end_template_offset    = this->binary_->rva_to_offset(stop_data_rva);

    const size_t size_to_read = end_template_offset - start_template_offset;

    try {
      if (size_to_read > Parser::MAX_DATA_SIZE) {
        LOG(WARNING) << "TLS's template is too large!";
      } else {
        const uint8_t* template_ptr = reinterpret_cast<const uint8_t*>(
          this->stream_->read(start_template_offset, size_to_read));
        std::vector<uint8_t> template_data = {
          template_ptr,
          template_ptr + size_to_read
        };
        tls.data_template(std::move(template_data));
      }

    } catch (const read_out_of_bound&) {
      LOG(WARNING) << "TLS corrupted (data template)";
    } catch (const std::bad_alloc&) {
      LOG(WARNING) << "TLS corrupted (data template)";
    }
  }

  uint64_t callbacks_offset  = this->binary_->rva_to_offset(tls.addressof_callbacks() - imagebase);
  uint__ callback_rva = this->stream_->read_integer<uint__>(callbacks_offset);
  callbacks_offset += sizeof(uint__);

  size_t count = 0;
  while (static_cast<uint32_t>(callback_rva) > 0 and count < Parser::MAX_TLS_CALLBACKS) {
    tls.callbacks_.push_back(static_cast<uint64_t>(callback_rva));
    callback_rva = this->stream_->read_integer<uint__>(callbacks_offset);
    callbacks_offset += sizeof(uint__);
  }

  tls.directory_ = &(this->binary_->data_directory(DATA_DIRECTORY::TLS_TABLE));

  try {
    Section& section = this->binary_->section_from_offset(offset);
    tls.section_     = &section;
  } catch (const not_found&) {
    LOG(WARNING) << "No section associated with TLS";
  }
}


template<typename PE_T>
void Parser::parse_load_config(void) {
  using load_configuration_t    = typename PE_T::load_configuration_t;
  using load_configuration_v0_t = typename PE_T::load_configuration_v0_t;
  using load_configuration_v1_t = typename PE_T::load_configuration_v1_t;
  using load_configuration_v2_t = typename PE_T::load_configuration_v2_t;
  using load_configuration_v3_t = typename PE_T::load_configuration_v3_t;
  using load_configuration_v4_t = typename PE_T::load_configuration_v4_t;
  using load_configuration_v5_t = typename PE_T::load_configuration_v5_t;
  using load_configuration_v6_t = typename PE_T::load_configuration_v6_t;
  using load_configuration_v7_t = typename PE_T::load_configuration_v7_t;

  VLOG(VDEBUG) << "[+] Parsing Load Config";

  const uint32_t directory_size = this->binary_->data_directory(DATA_DIRECTORY::LOAD_CONFIG_TABLE).size();

  const uint32_t ldc_rva = this->binary_->data_directory(DATA_DIRECTORY::LOAD_CONFIG_TABLE).RVA();
  const uint64_t offset  = this->binary_->rva_to_offset(ldc_rva);

  const uint32_t size_from_header = this->stream_->read_integer<uint32_t>(offset);

  if (directory_size != size_from_header) {
    LOG(WARNING) << "The size of directory '" << to_string(DATA_DIRECTORY::LOAD_CONFIG_TABLE)
                 << "' is different from the size in the load configuration header";
  }

  const uint32_t size = std::min<uint32_t>(directory_size, size_from_header);
  size_t current_size = 0;
  WIN_VERSION version_found = WIN_VERSION::WIN_UNKNOWN;
  for (auto&& p : PE_T::load_configuration_sizes) {
    if (p.second > current_size and p.second <= size) {
      std::tie(version_found, current_size) = p;
    }
  }

  VLOG(VDEBUG) << "Version found: " << std::dec << to_string(version_found) << "(Size: 0x" << std::hex << size << ")";
  std::unique_ptr<LoadConfiguration> ld_conf;
  switch (version_found) {

    case WIN_VERSION::WIN_SEH:
      {

        const load_configuration_v0_t* header = reinterpret_cast<const load_configuration_v0_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v0_t)));
        ld_conf = std::unique_ptr<LoadConfigurationV0>{new LoadConfigurationV0{header}};
        break;
      }

    case WIN_VERSION::WIN8_1:
      {

        const load_configuration_v1_t* header = reinterpret_cast<const load_configuration_v1_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v1_t)));
        ld_conf = std::unique_ptr<LoadConfigurationV1>{new LoadConfigurationV1{header}};
        break;
      }

    case WIN_VERSION::WIN10_0_9879:
      {

        const load_configuration_v2_t* header = reinterpret_cast<const load_configuration_v2_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v2_t)));
        ld_conf = std::unique_ptr<LoadConfigurationV2>{new LoadConfigurationV2{header}};
        break;
      }

    case WIN_VERSION::WIN10_0_14286:
      {

        const load_configuration_v3_t* header = reinterpret_cast<const load_configuration_v3_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v3_t)));

        ld_conf = std::unique_ptr<LoadConfigurationV3>{new LoadConfigurationV3{header}};
        break;
      }

    case WIN_VERSION::WIN10_0_14383:
      {

        const load_configuration_v4_t* header = reinterpret_cast<const load_configuration_v4_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v4_t)));

        ld_conf = std::unique_ptr<LoadConfigurationV4>{new LoadConfigurationV4{header}};
        break;
      }

    case WIN_VERSION::WIN10_0_14901:
      {

        const load_configuration_v5_t* header = reinterpret_cast<const load_configuration_v5_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v5_t)));

        ld_conf = std::unique_ptr<LoadConfigurationV5>{new LoadConfigurationV5{header}};
        break;
      }

    case WIN_VERSION::WIN10_0_15002:
      {

        const load_configuration_v6_t* header = reinterpret_cast<const load_configuration_v6_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v6_t)));

        ld_conf = std::unique_ptr<LoadConfigurationV6>{new LoadConfigurationV6{header}};
        break;
      }

    case WIN_VERSION::WIN10_0_16237:
      {

        const load_configuration_v7_t* header = reinterpret_cast<const load_configuration_v7_t*>(
          this->stream_->read(offset, sizeof(load_configuration_v7_t)));

        ld_conf = std::unique_ptr<LoadConfigurationV7>{new LoadConfigurationV7{header}};
        break;
      }

    case WIN_VERSION::WIN_UNKNOWN:
    default:
      {

        const load_configuration_t* header = reinterpret_cast<const load_configuration_t*>(
          this->stream_->read(offset, sizeof(load_configuration_t)));
        ld_conf = std::unique_ptr<LoadConfiguration>{new LoadConfiguration{header}};
      }
  }

  this->binary_->load_configuration_ = ld_conf.release();
  this->binary_->has_configuration_ = true;



}


}
}
