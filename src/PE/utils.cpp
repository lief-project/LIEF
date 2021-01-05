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
#include <algorithm>
#include <fstream>
#include <iterator>
#include <exception>
#include <string>
#include <numeric>
#include <iomanip>
#include <sstream>
#include <string>

#include "logging.hpp"
#include "mbedtls/md5.h"

#include "LIEF/exception.hpp"

#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/ImportEntry.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "utils/ordinals_lookup_tables/libraries_table.hpp"

namespace LIEF {
namespace PE {

bool is_pe(const std::string& file) {
  std::ifstream binary(file, std::ios::in | std::ios::binary);
  if (not binary) {
    LIEF_ERR("Unable to open the file!");
    return false;
  }

  uint64_t file_size;
  binary.unsetf(std::ios::skipws);
  binary.seekg(0, std::ios::end);
  file_size = binary.tellg();
  binary.seekg(0, std::ios::beg);


  if (file_size < sizeof(pe_dos_header)) {
    LIEF_ERR("File too small");
    return false;
  }

  char magic[2];
  pe_dos_header dos_header;
  binary.read(magic, sizeof(magic));
  if (magic[0] != 'M' or magic[1] != 'Z') {
    return false;
  }

  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&dos_header), sizeof(pe_dos_header));
  if (dos_header.AddressOfNewExeHeader >= file_size) {
    return false;
  }
  char signature[sizeof(PE_Magic)];
  binary.seekg(dos_header.AddressOfNewExeHeader, std::ios::beg);
  binary.read(signature, sizeof(PE_Magic));
  return std::equal(std::begin(signature), std::end(signature), std::begin(PE_Magic));
}


bool is_pe(const std::vector<uint8_t>& raw) {

  if (raw.size() < sizeof(pe_dos_header)) {
    return false;
  }

  const pe_dos_header* dos_header = reinterpret_cast<const pe_dos_header*>(raw.data());
  if (raw[0] != 'M' or raw[1] != 'Z') {
    return false;
  }

  if ((dos_header->AddressOfNewExeHeader + sizeof(pe_header)) >= raw.size()) {
    return false;
  }

  VectorStream raw_stream(raw);
  raw_stream.setpos(dos_header->AddressOfNewExeHeader);
  auto signature = raw_stream.read_array<char>(sizeof(PE_Magic), /* check bounds */ true);

  return std::equal(signature, signature + sizeof(PE_Magic), std::begin(PE_Magic));
}



PE_TYPE get_type(const std::string& file) {
  if (not is_pe(file)) {
    throw LIEF::bad_format("This file is not a PE binary");
  }

  std::ifstream binary(file, std::ios::in | std::ios::binary);
  if (not binary) {
    throw LIEF::bad_file("Unable to open the file");
  }


  pe_dos_header          dos_header;
  pe32_optional_header   optional_header;
  binary.seekg(0, std::ios::beg);

  binary.read(reinterpret_cast<char*>(&dos_header), sizeof(pe_dos_header));

  binary.seekg(dos_header.AddressOfNewExeHeader + sizeof(pe_header), std::ios::beg);
  binary.read(reinterpret_cast<char*>(&optional_header), sizeof(pe32_optional_header));
  PE_TYPE type = static_cast<PE_TYPE>(optional_header.Magic);

  if (type == PE_TYPE::PE32 or type == PE_TYPE::PE32_PLUS) {
    return type;
  } else {
    throw LIEF::bad_format("This file is not PE32 or PE32+");
  }

}

PE_TYPE get_type(const std::vector<uint8_t>& raw) {
  if (not is_pe(raw)) {
    throw LIEF::bad_format("This file is not a PE binary");
  }

  VectorStream raw_stream = VectorStream(raw);

  const pe_dos_header* dos_header = &raw_stream.read<pe_dos_header>();
  raw_stream.setpos(dos_header->AddressOfNewExeHeader + sizeof(pe_header));
  const pe32_optional_header* optional_header = &raw_stream.read<pe32_optional_header>();

  PE_TYPE type = static_cast<PE_TYPE>(optional_header->Magic);

  if (type == PE_TYPE::PE32 or type == PE_TYPE::PE32_PLUS) {
    return type;
  } else {
    throw LIEF::bad_format("This file is not PE32 or PE32+");
  }

}


std::string get_imphash(const Binary& binary) {
  uint8_t md5_buffer[16];
  if (not binary.has_imports()) {
    return std::to_string(0);
  }

  auto to_lower = [] (const std::string& str) {
    std::string lower = str;
    std::transform(
      std::begin(str),
      std::end(str),
      std::begin(lower),
      ::tolower);
    return lower;
  };
  it_const_imports imports = binary.imports();

  std::string import_list;
  for (const Import& imp : imports) {
    Import resolved = resolve_ordinals(imp);
    size_t ext_idx = resolved.name().find_last_of(".");
    std::string name_without_ext = resolved.name();

    if (ext_idx != std::string::npos) {
      name_without_ext = name_without_ext.substr(0, ext_idx);
    }

    std::string entries_string;
    for (const ImportEntry& e : resolved.entries()) {
      if (e.is_ordinal()) {
        entries_string += name_without_ext + ".#" + std::to_string(e.ordinal());
      } else {
        entries_string += name_without_ext + "." + e.name();
      }
    }
    import_list += to_lower(entries_string);
  }

  std::sort(
      std::begin(import_list),
      std::end(import_list),
      std::less<char>());

  mbedtls_md5(
      reinterpret_cast<const uint8_t*>(import_list.data()),
      import_list.size(),
      md5_buffer);

  std::string output_hex = std::accumulate(
      std::begin(md5_buffer),
      std::end(md5_buffer),
      std::string{},
      [] (const std::string& a, uint8_t b) {
        std::stringstream ss;
        ss << std::hex;
        ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(b);
        return a + ss.str();
      });

  return output_hex;
}


Import resolve_ordinals(const Import& import, bool strict) {

  it_const_import_entries entries = import.entries();

  if (std::all_of(
        std::begin(entries),
        std::end(entries),
        [] (const ImportEntry& entry) {
          return not entry.is_ordinal();
        })) {
    LIEF_DEBUG("All imports use name. No ordinal!");
    return import;
  }

  std::string name = import.name();
  std::transform(
      std::begin(name),
      std::end(name),
      std::begin(name),
      ::tolower);

  auto&& it_library_lookup = ordinals_library_tables.find(name);
  if (it_library_lookup == std::end(ordinals_library_tables)) {
    std::string msg = "Ordinal lookup table for '" + name + "' not implemented";
    if (strict) {
      throw not_found(msg);
    }
    LIEF_DEBUG("{}", msg);
    return import;
  }
  Import resolved_import = import;
  for (ImportEntry& entry : resolved_import.entries()) {
    if (entry.is_ordinal()) {
      LIEF_DEBUG("Dealing with: {}", entry);
      auto&& it_entry = it_library_lookup->second.find(static_cast<uint32_t>(entry.ordinal()));
      if (it_entry == std::end(it_library_lookup->second)) {
        if (strict) {
          throw not_found("Unable to resolve ordinal: " + std::to_string(entry.ordinal()));
        }
        LIEF_DEBUG("Unable to resolve ordinal: #{:d}", entry.ordinal());
        continue;
      }
      entry.data(0);
      entry.name(it_entry->second);
    }
  }

  return resolved_import;
}
ALGORITHMS algo_from_oid(const std::string& oid) {
  static const std::unordered_map<std::string, ALGORITHMS> OID_MAP = {
    { "2.16.840.1.101.3.4.2.3", ALGORITHMS::SHA_512 },
    { "2.16.840.1.101.3.4.2.2", ALGORITHMS::SHA_384 },
    { "2.16.840.1.101.3.4.2.1", ALGORITHMS::SHA_256 },
    { "1.3.14.3.2.26",          ALGORITHMS::SHA_1   },

    { "1.2.840.113549.2.5",     ALGORITHMS::MD5 },
    { "1.2.840.113549.2.4",     ALGORITHMS::MD4 },
    { "1.2.840.113549.2.2",     ALGORITHMS::MD2 },

    { "1.2.840.113549.1.1.1",   ALGORITHMS::RSA },
    { "1.2.840.10045.2.1",      ALGORITHMS::EC  },

    { "1.2.840.113549.1.1.4",   ALGORITHMS::MD5_RSA        },
    { "1.2.840.10040.4.3",      ALGORITHMS::SHA1_DSA       },
    { "1.2.840.113549.1.1.5",   ALGORITHMS::SHA1_RSA       },
    { "1.2.840.113549.1.1.11",  ALGORITHMS::SHA_256_RSA    },
    { "1.2.840.113549.1.1.12",  ALGORITHMS::SHA_384_RSA    },
    { "1.2.840.113549.1.1.13",  ALGORITHMS::SHA_512_RSA    },
    { "1.2.840.10045.4.1",      ALGORITHMS::SHA1_ECDSA     },
    { "1.2.840.10045.4.3.2",    ALGORITHMS::SHA_256_ECDSA  },
    { "1.2.840.10045.4.3.3",    ALGORITHMS::SHA_384_ECDSA  },
    { "1.2.840.10045.4.3.4",    ALGORITHMS::SHA_512_ECDSA  },
  };


  const auto& it = OID_MAP.find(oid.c_str());
  if (it == std::end(OID_MAP)) {
    return ALGORITHMS::UNKNOWN;
  }
  return it->second;
}


}
}
