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
#include <string.h>

#include "LIEF/utf8.h"
#include "LIEF/exception.hpp"

#include "LIEF/PE/utils.hpp"

namespace LIEF {
namespace PE {

bool is_pe(const std::string& file) {
  std::ifstream binary(file, std::ios::in | std::ios::binary);
  if (not binary) {
    throw LIEF::bad_file("Unable to open the file");
  }

  uint64_t file_size;
  binary.unsetf(std::ios::skipws);
  binary.seekg(0, std::ios::end);
  file_size = binary.tellg();
  binary.seekg(0, std::ios::beg);

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

  char signature[sizeof(PE_Magic)];
  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data() + dos_header->AddressOfNewExeHeader),
    reinterpret_cast<const uint8_t*>(raw.data() + dos_header->AddressOfNewExeHeader) + sizeof(signature),
    signature);

  return std::equal(std::begin(signature), std::end(signature), std::begin(PE_Magic));
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

  const pe_dos_header*          dos_header;
  const pe32_optional_header*   optional_header;

  dos_header      = reinterpret_cast<const pe_dos_header*>(raw.data());
  optional_header = reinterpret_cast<const pe32_optional_header*>(
      raw.data() +
      dos_header->AddressOfNewExeHeader +
      sizeof(pe_header));

  PE_TYPE type = static_cast<PE_TYPE>(optional_header->Magic);

  if (type == PE_TYPE::PE32 or type == PE_TYPE::PE32_PLUS) {
    return type;
  } else {
    throw LIEF::bad_format("This file is not PE32 or PE32+");
  }

}


std::string u16tou8(const std::u16string& string) {
  std::string name;
  utf8::utf16to8(std::begin(string), std::end(string), std::back_inserter(name));
  return name;
}

std::u16string u8tou16(const std::string& string) {
  std::u16string name;
  utf8::utf8to16(std::begin(string), std::end(string), std::back_inserter(name));
  return name;
}
}
}
