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
#include <algorithm>

#include "LIEF/Visitor.hpp"

#include "LIEF/PE/EnumToString.hpp"
#include "LIEF/PE/Header.hpp"
#include "PE/Structures.hpp"
#include "frozen.hpp"

#include <spdlog/fmt/fmt.h>

namespace LIEF {
namespace PE {

static constexpr std::array CHARACTERISTICS_LIST = {
  Header::CHARACTERISTICS::RELOCS_STRIPPED,
  Header::CHARACTERISTICS::EXECUTABLE_IMAGE,
  Header::CHARACTERISTICS::LINE_NUMS_STRIPPED,
  Header::CHARACTERISTICS::LOCAL_SYMS_STRIPPED,
  Header::CHARACTERISTICS::AGGRESSIVE_WS_TRIM,
  Header::CHARACTERISTICS::LARGE_ADDRESS_AWARE,
  Header::CHARACTERISTICS::BYTES_REVERSED_LO,
  Header::CHARACTERISTICS::NEED_32BIT_MACHINE,
  Header::CHARACTERISTICS::DEBUG_STRIPPED,
  Header::CHARACTERISTICS::REMOVABLE_RUN_FROM_SWAP,
  Header::CHARACTERISTICS::NET_RUN_FROM_SWAP,
  Header::CHARACTERISTICS::SYSTEM,
  Header::CHARACTERISTICS::DLL,
  Header::CHARACTERISTICS::UP_SYSTEM_ONLY,
  Header::CHARACTERISTICS::BYTES_REVERSED_HI
};


Header Header::create(PE_TYPE type) {
  Header hdr;
  const size_t sizeof_dirs = details::DEFAULT_NUMBER_DATA_DIRECTORIES *
                             sizeof(details::pe_data_directory);
  hdr.signature({ 'P', 'E', '\0', '\0' });
  hdr.sizeof_optional_header(type == PE_TYPE::PE32 ?
                             sizeof(details::pe32_optional_header) :
                             sizeof(details::pe64_optional_header) + sizeof_dirs);
  return hdr;
}

Header::Header(const details::pe_header& header) :
  machine_(static_cast<MACHINE_TYPES>(header.Machine)),
  nb_sections_(header.NumberOfSections),
  timedatestamp_(header.TimeDateStamp),
  pointerto_symtab_(header.PointerToSymbolTable),
  nb_symbols_(header.NumberOfSymbols),
  sizeof_opt_header_(header.SizeOfOptionalHeader),
  characteristics_(header.Characteristics)

{
  std::copy(std::begin(header.signature), std::end(header.signature),
            std::begin(signature_));
}

std::vector<Header::CHARACTERISTICS> Header::characteristics_list() const {
  std::vector<Header::CHARACTERISTICS> list;
  list.reserve(3);
  std::copy_if(CHARACTERISTICS_LIST.begin(), CHARACTERISTICS_LIST.end(),
               std::back_inserter(list),
               [this] (CHARACTERISTICS c) { return has_characteristic(c); });

  return list;
}

void Header::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const Header& entry) {
  const Header::signature_t& sig = entry.signature();
  const std::string& signature_str =
    fmt::format("{:02x} {:02x} {:02x} {:02x}",
                sig[0], sig[1], sig[2], sig[3]);

  const auto& list = entry.characteristics_list();
  std::vector<std::string> list_str;
  list_str.reserve(list.size());
  std::transform(list.begin(), list.end(), std::back_inserter(list_str),
                 [] (const auto c) { return to_string(c); });

  os << fmt::format("Signature:               {}\n", signature_str)
     << fmt::format("Machine:                 {}\n", to_string(entry.machine()))
     << fmt::format("Number of sections:      {}\n", entry.numberof_sections())
     << fmt::format("Pointer to symbol table: 0x{:x}\n", entry.pointerto_symbol_table())
     << fmt::format("Number of symbols:       {}\n", entry.numberof_symbols())
     << fmt::format("Size of optional header: 0x{:x}\n", entry.sizeof_optional_header())
     << fmt::format("Characteristics:         {}\n", fmt::join(list_str, ", "))
     << fmt::format("Timtestamp:              {}\n", entry.time_date_stamp());

  return os;

}

const char* to_string(Header::MACHINE_TYPES e) {
  CONST_MAP(Header::MACHINE_TYPES, const char*, 25) enumStrings {
    { Header::MACHINE_TYPES::UNKNOWN,   "UNKNOWN" },
    { Header::MACHINE_TYPES::AM33,      "AM33" },
    { Header::MACHINE_TYPES::AMD64,     "AMD64" },
    { Header::MACHINE_TYPES::ARM,       "ARM" },
    { Header::MACHINE_TYPES::ARMNT,     "ARMNT" },
    { Header::MACHINE_TYPES::ARM64,     "ARM64" },
    { Header::MACHINE_TYPES::EBC,       "EBC" },
    { Header::MACHINE_TYPES::I386,      "I386" },
    { Header::MACHINE_TYPES::IA64,      "IA64" },
    { Header::MACHINE_TYPES::M32R,      "M32R" },
    { Header::MACHINE_TYPES::MIPS16,    "MIPS16" },
    { Header::MACHINE_TYPES::MIPSFPU,   "MIPSFPU" },
    { Header::MACHINE_TYPES::MIPSFPU16, "MIPSFPU16" },
    { Header::MACHINE_TYPES::POWERPC,   "POWERPC" },
    { Header::MACHINE_TYPES::POWERPCFP, "POWERPCFP" },
    { Header::MACHINE_TYPES::R4000,     "R4000" },
    { Header::MACHINE_TYPES::RISCV32,   "RISCV32" },
    { Header::MACHINE_TYPES::RISCV64,   "RISCV64" },
    { Header::MACHINE_TYPES::RISCV128,  "RISCV128" },
    { Header::MACHINE_TYPES::SH3,       "SH3" },
    { Header::MACHINE_TYPES::SH3DSP,    "SH3DSP" },
    { Header::MACHINE_TYPES::SH4,       "SH4" },
    { Header::MACHINE_TYPES::SH5,       "SH5" },
    { Header::MACHINE_TYPES::THUMB,     "THUMB" },
    { Header::MACHINE_TYPES::WCEMIPSV2, "WCEMIPSV2" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNKNOWN" : it->second;
}

const char* to_string(Header::CHARACTERISTICS e) {
  CONST_MAP(Header::CHARACTERISTICS, const char*, 16) enumStrings {
    { Header::CHARACTERISTICS::NONE,                    "NONE" },
    { Header::CHARACTERISTICS::RELOCS_STRIPPED,         "RELOCS_STRIPPED" },
    { Header::CHARACTERISTICS::EXECUTABLE_IMAGE,        "EXECUTABLE_IMAGE" },
    { Header::CHARACTERISTICS::LINE_NUMS_STRIPPED,      "LINE_NUMS_STRIPPED" },
    { Header::CHARACTERISTICS::LOCAL_SYMS_STRIPPED,     "LOCAL_SYMS_STRIPPED" },
    { Header::CHARACTERISTICS::AGGRESSIVE_WS_TRIM,      "AGGRESSIVE_WS_TRIM" },
    { Header::CHARACTERISTICS::LARGE_ADDRESS_AWARE,     "LARGE_ADDRESS_AWARE" },
    { Header::CHARACTERISTICS::BYTES_REVERSED_LO,       "BYTES_REVERSED_LO" },
    { Header::CHARACTERISTICS::NEED_32BIT_MACHINE,      "NEED_32BIT_MACHINE" },
    { Header::CHARACTERISTICS::DEBUG_STRIPPED,          "DEBUG_STRIPPED" },
    { Header::CHARACTERISTICS::REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
    { Header::CHARACTERISTICS::NET_RUN_FROM_SWAP,       "NET_RUN_FROM_SWAP" },
    { Header::CHARACTERISTICS::SYSTEM,                  "SYSTEM" },
    { Header::CHARACTERISTICS::DLL,                     "DLL" },
    { Header::CHARACTERISTICS::UP_SYSTEM_ONLY,          "UP_SYSTEM_ONLY" },
    { Header::CHARACTERISTICS::BYTES_REVERSED_HI,       "BYTES_REVERSED_HI" }
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "NONE" : it->second;
}




}
}
