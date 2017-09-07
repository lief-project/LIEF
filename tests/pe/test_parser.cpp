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
#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include <yaml-cpp/yaml.h>

#include <LIEF/PE.hpp>

#include "utils.hpp"

extern const YAML::Node config = YAML::LoadFile(std::string(PATH_TO_CONFIG) + "/config.yaml");

using namespace LIEF::PE;

TEST_CASE("Test parse", "[pe][parser]")
{

  using namespace Catch::Generators;
  // Get test cases
  std::vector<std::string> pe_test_cases = Test::get_test_cases();

  // Get one
  std::vector<std::string>::iterator test_case = between(
      std::begin(pe_test_cases),
      std::prev(std::end(pe_test_cases)));


  YAML::Node parameters = YAML::LoadFile(config[*test_case]["config_file"].as<std::string>());

  // Parse binary
  std::unique_ptr<const Binary> binary{Parser::parse(config[*test_case]["binary_path"].as<std::string>())};

  // Raw data
  std::ifstream binfile(config[*test_case]["binary_path"].as<std::string>(), std::ios::in | std::ios::binary);
  REQUIRE(binfile);
  std::vector<uint8_t> raw = {std::istreambuf_iterator<char>(binfile), std::istreambuf_iterator<char>()};

  // Dos Header
  // ==========
  SECTION("Dos Header") {
    REQUIRE(binary->dos_header().magic() == parameters["dos_header"]["e_magic"].as<unsigned int>());
  }


  // Header
  // ======
  SECTION("Header") {
    const Header& header = binary->header();
    REQUIRE(
      static_cast<uint32_t>(header.machine()) ==
      parameters["header"]["Machine"].as<uint32_t>());

    REQUIRE(
        static_cast<uint16_t>(header.numberof_sections()) ==
        parameters["header"]["NumberOfSections"].as<uint16_t>());

    REQUIRE(
        static_cast<uint32_t>(header.time_date_stamp()) ==
        parameters["header"]["TimeDateStamp"].as<uint32_t>());

    REQUIRE(
        static_cast<uint32_t>(header.pointerto_symbol_table()) ==
        parameters["header"]["PointerToSymbolTable"].as<uint32_t>());

    REQUIRE(
        static_cast<uint32_t>(header.numberof_symbols()) ==
        parameters["header"]["NumberOfSymbols"].as<uint32_t>());

    REQUIRE(
        static_cast<uint16_t>(header.sizeof_optional_header()) ==
        parameters["header"]["SizeOfOptionalHeader"].as<uint16_t>());

    REQUIRE(
        static_cast<uint16_t>(header.characteristics()) ==
        parameters["header"]["Characteristics"].as<uint16_t>());
  }


  // Optional Header
  // ===============
  SECTION("Optional Header") {
    const OptionalHeader& optional_header = binary->optional_header();

    REQUIRE(
        static_cast<uint32_t>(optional_header.magic()) ==
        parameters["optional_header"]["Magic"].as<uint32_t>());

    REQUIRE(
        optional_header.major_linker_version() ==
        parameters["optional_header"]["MajorLinkerVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.minor_linker_version() ==
        parameters["optional_header"]["MinorLinkerVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.sizeof_code() ==
        parameters["optional_header"]["SizeOfCode"].as<uint32_t>());

    REQUIRE(
        optional_header.sizeof_initialized_data() ==
        parameters["optional_header"]["SizeOfInitializedData"].as<uint32_t>());

    REQUIRE(
        optional_header.sizeof_uninitialized_data() ==
        parameters["optional_header"]["SizeOfUninitializedData"].as<uint32_t>());

    REQUIRE(
        optional_header.addressof_entrypoint() ==
        parameters["optional_header"]["AddressOfEntryPoint"].as<uint32_t>());

    REQUIRE(
        optional_header.baseof_code() ==
        parameters["optional_header"]["BaseOfCode"].as<uint32_t>());

    if (binary->type() == LIEF::PE::PE_TYPE::PE32) {
      REQUIRE(
          optional_header.baseof_data() ==
          parameters["optional_header"]["BaseOfData"].as<uint32_t>());
    }

    REQUIRE(
        optional_header.imagebase() ==
        parameters["optional_header"]["ImageBase"].as<uint64_t>());

    REQUIRE(
        optional_header.section_alignment() ==
        parameters["optional_header"]["SectionAlignment"].as<uint32_t>());

    REQUIRE(
        optional_header.file_alignment() ==
        parameters["optional_header"]["FileAlignment"].as<uint32_t>());

    REQUIRE(
        optional_header.major_operating_system_version() ==
        parameters["optional_header"]["MajorOperatingSystemVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.minor_operating_system_version() ==
        parameters["optional_header"]["MinorOperatingSystemVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.major_image_version() ==
        parameters["optional_header"]["MajorImageVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.minor_image_version() ==
        parameters["optional_header"]["MinorImageVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.major_subsystem_version() ==
        parameters["optional_header"]["MajorSubsystemVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.minor_subsystem_version() ==
        parameters["optional_header"]["MinorSubsystemVersion"].as<uint32_t>());

    REQUIRE(
        optional_header.win32_version_value() ==
        parameters["optional_header"]["Reserved1"].as<uint32_t>());

    REQUIRE(
        optional_header.sizeof_image() ==
        parameters["optional_header"]["SizeOfImage"].as<uint32_t>());

    REQUIRE(
        optional_header.sizeof_headers() ==
        parameters["optional_header"]["SizeOfHeaders"].as<uint32_t>());

    REQUIRE(
        optional_header.checksum() ==
        parameters["optional_header"]["CheckSum"].as<uint32_t>());

    REQUIRE(
        static_cast<uint32_t>(optional_header.subsystem()) ==
        parameters["optional_header"]["Subsystem"].as<uint32_t>());

    REQUIRE(
        optional_header.dll_characteristics() ==
        parameters["optional_header"]["DllCharacteristics"].as<uint32_t>());

    REQUIRE(
        optional_header.sizeof_stack_reserve() ==
        parameters["optional_header"]["SizeOfStackReserve"].as<uint64_t>());

    REQUIRE(
        optional_header.sizeof_stack_commit() ==
        parameters["optional_header"]["SizeOfStackCommit"].as<uint64_t>());

    REQUIRE(
        optional_header.sizeof_heap_reserve() ==
        parameters["optional_header"]["SizeOfHeapReserve"].as<uint64_t>());

    REQUIRE(
        optional_header.sizeof_heap_commit() ==
        parameters["optional_header"]["SizeOfHeapCommit"].as<uint64_t>());

    REQUIRE(
        optional_header.loader_flags() ==
        parameters["optional_header"]["LoaderFlags"].as<uint32_t>());

    REQUIRE(
        optional_header.numberof_rva_and_size() ==
        parameters["optional_header"]["NumberOfRvaAndSizes"].as<uint32_t>());
  }

  // Sections
  // ========
  SECTION("Section") {
    it_const_sections sections = binary->sections();

    REQUIRE(
      sections.size() ==
      parameters["header"]["NumberOfSections"].as<uint16_t>());

    if(parameters["sections"]) {
      for (size_t i = 0; i < parameters["sections"].size(); ++i) {
        const Section& section = sections[i];
        REQUIRE(
            parameters["sections"][i]["name"].as<std::string>() ==
            section.name());

        REQUIRE(
            parameters["sections"][i]["Misc_VirtualSize"].as<uint32_t>() ==
            section.virtual_size());

        REQUIRE(
            parameters["sections"][i]["VirtualAddress"].as<uint32_t>() ==
            section.virtual_address());

        REQUIRE(
            parameters["sections"][i]["SizeOfRawData"].as<uint32_t>() ==
            section.sizeof_raw_data());

        REQUIRE(
            parameters["sections"][i]["PointerToRawData"].as<uint32_t>() ==
            section.pointerto_raw_data());

        REQUIRE(
            parameters["sections"][i]["PointerToRelocations"].as<uint32_t>() ==
            section.pointerto_relocation());

        REQUIRE(
            parameters["sections"][i]["PointerToLinenumbers"].as<uint32_t>() ==
            section.pointerto_line_numbers());

        REQUIRE(
            parameters["sections"][i]["NumberOfRelocations"].as<uint32_t>() ==
            section.numberof_relocations());

        REQUIRE(
            parameters["sections"][i]["NumberOfLinenumbers"].as<uint32_t>() ==
            section.numberof_line_numbers());

        REQUIRE(
            parameters["sections"][i]["Characteristics"].as<uint32_t>() ==
            section.characteristics());
      }
    }
  }


  // Imports
  // =======
  SECTION("Imports") {
    if (not binary->has_imports()) {
      return;
    }

    it_const_imports imports = binary->imports();

    REQUIRE(
        imports.size() ==
        parameters["imports"].size());

    for (size_t i = 0; i < parameters["imports"].size(); ++i) {
      const Import& import = imports[i];
      it_const_import_entries entries = import.entries();

      REQUIRE(
          parameters["imports"][i]["name"].as<std::string>() ==
          import.name());

      REQUIRE(
          parameters["imports"][i]["entries"].size() ==
          entries.size());

      for (size_t j = 0; j < parameters["imports"][i]["entries"].size(); ++j) {
        const ImportEntry& entry = entries[j];
        if (not parameters["imports"][i]["entries"][j]["name"].IsNull()) {
          REQUIRE(
            parameters["imports"][i]["entries"][j]["name"].as<std::string>() ==
            entry.name());
        }
      }
    }
  }

  // TLS
  // ===
  SECTION("TLS") {
    if(not binary->has_tls() or not parameters["tls"]) {
      return;
    }

    const TLS& tls = binary->tls();
    REQUIRE(
        parameters["tls"]["StartAddressOfRawData"].as<uint64_t>() ==
        tls.addressof_raw_data().first);

    REQUIRE(
        parameters["tls"]["EndAddressOfRawData"].as<uint64_t>() ==
        tls.addressof_raw_data().second);

    REQUIRE(
        parameters["tls"]["AddressOfIndex"].as<uint64_t>() ==
        tls.addressof_index());

    REQUIRE(
        parameters["tls"]["AddressOfCallBacks"].as<uint64_t>() ==
        tls.addressof_callbacks());

    REQUIRE(
        parameters["tls"]["SizeOfZeroFill"].as<uint64_t>() ==
        tls.sizeof_zero_fill());

    REQUIRE(
        parameters["tls"]["Characteristics"].as<uint64_t>() ==
        tls.characteristics());
  }




}


