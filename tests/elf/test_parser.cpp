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

#include <LIEF/ELF.hpp>

#include "utils.hpp"

extern const YAML::Node config = YAML::LoadFile(std::string(PATH_TO_CONFIG) + "/config.yaml");

using namespace LIEF::ELF;

TEST_CASE("Test parse", "[elf][parser]")
{

  using namespace Catch::Generators;
  // Get test cases
  std::vector<std::string> elf_test_cases = Test::get_test_cases();

  // Get one
  std::vector<std::string>::iterator test_case = between(
      std::begin(elf_test_cases),
      std::prev(std::end(elf_test_cases)));


  YAML::Node parameters = YAML::LoadFile(config[*test_case]["config_file"].as<std::string>());

  DYNSYM_COUNT_METHODS mtd = DYNSYM_COUNT_METHODS::COUNT_AUTO;
  if (*test_case == "test_gcc_32") {
    mtd = DYNSYM_COUNT_METHODS::COUNT_SECTION;
  }
  // Parse binary
  std::unique_ptr<const Binary> binary{Parser::parse(config[*test_case]["binary_path"].as<std::string>(), mtd)};

  INFO("Binary used: " << binary->name());

  // Raw data
  std::ifstream binfile(config[*test_case]["binary_path"].as<std::string>(), std::ios::in | std::ios::binary);
  REQUIRE(binfile);
  std::vector<uint8_t> raw = {std::istreambuf_iterator<char>(binfile), std::istreambuf_iterator<char>()};

  // Header
  // ======
  SECTION("Header") {
    const Header& header = binary->header();
    REQUIRE(header.numberof_sections()      == parameters["Header"]["nbShdr"].as<unsigned int>());
    REQUIRE(header.numberof_segments()      == parameters["Header"]["nbPhdr"].as<unsigned int>());
    REQUIRE(header.entrypoint()             == parameters["Header"]["entryPoint"].as<unsigned long long>());
    REQUIRE(header.program_headers_offset() == parameters["Header"]["offsetToPhdr"].as<unsigned long long>());
    REQUIRE(header.section_headers_offset() == parameters["Header"]["offsetToShdr"].as<unsigned long long>());
  }

  // Sections
  // ========
  SECTION("Sections") {

    REQUIRE(binary->sections().size() == parameters["Header"]["nbShdr"].as<unsigned int>());

    if (parameters["Sections"]) {
      it_const_sections sections = binary->sections();
      for (size_t i = 0; i < parameters["Sections"].size(); ++i) {
        const Section& section = sections[i];
        //name[:17] because readelf provide only the first 16 char
        REQUIRE(parameters["Sections"][i]["name"].as<std::string>() == section.name().substr(0,17));

        REQUIRE(parameters["Sections"][i]["offset"].as<unsigned long long>() == section.file_offset());

        REQUIRE(parameters["Sections"][i]["address"].as<unsigned long long>() == section.virtual_address());

        REQUIRE(parameters["Sections"][i]["size"].as<unsigned long long>() == section.size());

        REQUIRE(parameters["Sections"][i]["nb"].as<unsigned int>() == i);

        if (parameters["Sections"][i]["size"].as<unsigned long long>() > 0 and
            section.type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS) {
          REQUIRE(
            std::vector<uint8_t>(
              raw.data() + parameters["Sections"][i]["offset"].as<unsigned long long>(),
              raw.data() + parameters["Sections"][i]["offset"].as<unsigned long long>() + parameters["Sections"][i]["size"].as<unsigned long long>()) ==
              section.content()
            );
        }
      }
    }
  }

  // Segments
  // ========
  SECTION("Segments") {
    REQUIRE(binary->segments().size() == parameters["Header"]["nbPhdr"].as<unsigned int>());
    if (parameters["Segments"]) {
      it_const_segments segments = binary->segments();
      for (size_t i = 0; i < parameters["Segments"].size(); ++i) {
        const Segment& segment = segments[i];
        REQUIRE(parameters["Segments"][i]["fSize"].as<unsigned long long>()    == segment.physical_size());
        REQUIRE(parameters["Segments"][i]["offset"].as<unsigned long long>()   == segment.file_offset());
        REQUIRE(parameters["Segments"][i]["pAddress"].as<unsigned long long>() == segment.physical_address());
        REQUIRE(parameters["Segments"][i]["vAddress"].as<unsigned long long>() == segment.virtual_address());
        REQUIRE(parameters["Segments"][i]["fSize"].as<unsigned long long>()    == segment.physical_size());
        REQUIRE(parameters["Segments"][i]["vSize"].as<unsigned long long>()    == segment.virtual_size());
        if (parameters["Segments"][i]["fSize"].as<unsigned long long>() > 0) {
          REQUIRE(
            std::vector<uint8_t>(
              raw.data() + parameters["Segments"][i]["offset"].as<unsigned long long>(),
              raw.data() + parameters["Segments"][i]["offset"].as<unsigned long long>() + parameters["Segments"][i]["fSize"].as<unsigned long long>()) ==
            segment.content());
        }
      }
    }
  }

  // Dynamic symbols
  // ===============
  SECTION("Dynamic Symbols") {
    if (parameters["DynamicSymbols"]) {
      // +1 for the null entry
      REQUIRE(parameters["DynamicSymbols"].size() == binary->dynamic_symbols().size());

      it_const_symbols dynamic_symbols = binary->dynamic_symbols();
      for (size_t i = 0; i < parameters["DynamicSymbols"].size(); ++i) {
        const Symbol& symbol = dynamic_symbols[i];
        REQUIRE(parameters["DynamicSymbols"][i]["name"].as<std::string>() == symbol.name().substr(0, 25));
      }
    }
  }

  // Static symbols
  // ===============
  SECTION("Static Symbols") {
    if (parameters["StaticSymbols"]) {
      it_const_symbols static_symbols = binary->static_symbols();
      for (size_t i = 0; i < parameters["StaticSymbols"].size(); ++i) {
        const Symbol& symbol = static_symbols[parameters["StaticSymbols"][i]["num"].as<size_t>()];
        REQUIRE(parameters["StaticSymbols"][i]["name"].as<std::string>() == symbol.name().substr(0, 25));
      }
    }
  }


  // Dynamic relocations
  // ===================
  SECTION("Dynamic relocations") {
    if (parameters["DynamicReloc"]) {
      REQUIRE(parameters["DynamicReloc"].size() == binary->dynamic_relocations().size());
      it_const_dynamic_relocations relocations = binary->dynamic_relocations();
      for (size_t i = 0; i < parameters["DynamicReloc"].size(); ++i) {
        const Relocation& relocation = relocations[i];
        REQUIRE(parameters["DynamicReloc"][i]["name"].as<std::string>() == relocation.symbol().name().substr(0, 22));
        REQUIRE(parameters["DynamicReloc"][i]["offset"].as<uint64_t>()  == relocation.address());
      }
    }
  }


  // .plt.got relocations
  // ====================
  SECTION(".plt.got relocations") {
    if (parameters["PltGotReloc"]) {
      REQUIRE(parameters["PltGotReloc"].size() == binary->pltgot_relocations().size());
      it_const_pltgot_relocations relocations = binary->pltgot_relocations();
      for (size_t i = 0; i < parameters["PltGotReloc"].size(); ++i) {
        const Relocation& relocation = relocations[i];
        if (parameters["PltGotReloc"][i]["name"].as<std::string>().size() > 0) {
          REQUIRE(parameters["PltGotReloc"][i]["name"].as<std::string>() == relocation.symbol().name().substr(0, 22));
        }
        REQUIRE(parameters["PltGotReloc"][i]["offset"].as<uint64_t>() == relocation.address());
      }
    }
  }



}


