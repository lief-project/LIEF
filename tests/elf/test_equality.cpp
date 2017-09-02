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

#include <LIEF/exception.hpp>
#include <LIEF/ELF.hpp>

#include "utils.hpp"

extern const YAML::Node config = YAML::LoadFile(std::string(PATH_TO_CONFIG) + "/config.yaml");

using namespace LIEF::ELF;

TEST_CASE("Test operator==", "[elf][internal]") {

  using namespace Catch::Generators;
  std::vector<std::string> elf_files = Test::get_elf_files();

  // Get one
  std::vector<std::string>::iterator elf_file = between(
      std::begin(elf_files),
      std::prev(std::end(elf_files)));


  const std::string& elf_file_str = *elf_file;

  if (elf_file_str.find("ELF32_x86_binary_tiny.bin") != std::string::npos) {
    INFO("Skip " << elf_file_str);
    return;
  }

  INFO("Binary used: " << *elf_file);

  std::unique_ptr<const Binary> binary;
  try {
     binary = std::unique_ptr<const Binary>{Parser::parse(*elf_file)};
  } catch (const LIEF::exception& e) {
    WARN("Can't parse: '" << *elf_file << "' (" << e.what() << ")");
    return;
  }

  SECTION("Header") {
    const Header& header_lhs = binary->header();
    Header header_rhs = header_lhs;
    REQUIRE(header_lhs == header_rhs);

    header_rhs.entrypoint(0xDEADBEEF);
    REQUIRE(header_lhs != header_rhs);
  }

  SECTION("Section") {
    for (const Section& section : binary->sections()) {
      {
        const Section& section_lhs = section;
        const Section& section_rhs = section;
        REQUIRE(section_lhs == section_rhs);
      }

      {
        Section section_lhs = section;
        const Section& section_rhs = section;
        REQUIRE(section_lhs == section_rhs);
      }
    }
  }


  SECTION("Segments") {
    for (const Segment& segment: binary->segments()) {
      {
        const Segment& segment_lhs = segment;
        const Segment& segment_rhs = segment;
        REQUIRE(segment_lhs == segment_rhs);
      }

      {
        Segment segment_lhs = segment;
        const Segment& segment_rhs = segment;
        REQUIRE(segment_lhs == segment_rhs);
      }
    }
  }


  SECTION("Static Symbols") {
    for (const Symbol& symbol: binary->static_symbols()) {
      {
        const Symbol& symbol_lhs = symbol;
        const Symbol& symbol_rhs = symbol;
        REQUIRE(symbol_lhs == symbol_rhs);
      }

      {
        Symbol symbol_lhs = symbol;
        const Symbol& symbol_rhs = symbol;
        //CHECK(symbol_lhs == symbol_rhs);
      }
    }
  }


  SECTION("Dynamic Symbols") {
    for (const Symbol& symbol: binary->dynamic_symbols()) {
      {
        const Symbol& symbol_lhs = symbol;
        const Symbol& symbol_rhs = symbol;
        REQUIRE(symbol_lhs == symbol_rhs);
      }

      {
        Symbol symbol_lhs = symbol;
        const Symbol& symbol_rhs = symbol;
        //CHECK(symbol_lhs == symbol_rhs);
      }
    }
  }

  SECTION("Dynamic Relocations") {
    for (const Relocation& relocation: binary->dynamic_relocations()) {
      {
        const Relocation& relocation_lhs = relocation;
        const Relocation& relocation_rhs = relocation;
        REQUIRE(relocation_lhs == relocation_rhs);
      }
      {
        Relocation relocation_lhs = relocation;
        const Relocation& relocation_rhs = relocation;
        //CHECK(symbol_lhs == symbol_rhs);
      }

    }
  }


  SECTION(".plt.got Relocations") {
    for (const Relocation& relocation: binary->pltgot_relocations()) {
      {
        const Relocation& relocation_lhs = relocation;
        const Relocation& relocation_rhs = relocation;
        REQUIRE(relocation_lhs == relocation_rhs);
      }
      {
        Relocation relocation_lhs = relocation;
        const Relocation& relocation_rhs = relocation;
        //CHECK(symbol_lhs == symbol_rhs);
      }
    }
  }

  SECTION("Symbols version") {
    for (const SymbolVersion& sv: binary->symbols_version()) {
      {
        const SymbolVersion& sv_lhs = sv;
        const SymbolVersion& sv_rhs = sv;
        REQUIRE(sv_lhs == sv_rhs);
      }
      {
        SymbolVersion sv_lhs = sv;
        const SymbolVersion& sv_rhs = sv;
        //REQUIRE(sv_lhs == sv_rhs);
      }
    }
  }

  SECTION("Symbols version definition") {
    for (const SymbolVersionDefinition& svd: binary->symbols_version_definition()) {
      {
        const SymbolVersionDefinition& svd_lhs = svd;
        const SymbolVersionDefinition& svd_rhs = svd;
        REQUIRE(svd_lhs == svd_rhs);
      }
      {
        SymbolVersionDefinition svd_lhs = svd;
        const SymbolVersionDefinition& svd_rhs = svd;
        //CHECK(svd_lhs == svd_rhs);
      }
    }
  }

  SECTION("Symbols version requirement") {
    for (const SymbolVersionRequirement& svr: binary->symbols_version_requirement()) {
      {
        const SymbolVersionRequirement& svr_lhs = svr;
        const SymbolVersionRequirement& svr_rhs = svr;
        REQUIRE(svr_lhs == svr_rhs);
      }
      {
        SymbolVersionRequirement svr_lhs = svr;
        const SymbolVersionRequirement& svr_rhs = svr;
        //CHECK(svd_lhs == svd_rhs);
      }
    }
  }
}
