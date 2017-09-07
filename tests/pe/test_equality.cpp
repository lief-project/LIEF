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
#include <LIEF/PE.hpp>

#include "utils.hpp"

extern const YAML::Node config = YAML::LoadFile(std::string(PATH_TO_CONFIG) + "/config.yaml");

using namespace LIEF::PE;

TEST_CASE("Test operator== and operator!=", "[pe][internal]") {

  using namespace Catch::Generators;
  std::vector<std::string> pe_files = Test::get_pe_files();

  // Get one
  std::vector<std::string>::iterator pe_file = between(
      std::begin(pe_files),
      std::prev(std::end(pe_files)));

  INFO("Binary used: " << *pe_file);
  std::unique_ptr<const Binary> binary_lhs;
  std::unique_ptr<const Binary> binary_rhs;
  try {
     binary_lhs = std::unique_ptr<const Binary>{Parser::parse(*pe_file)};
     binary_rhs = std::unique_ptr<const Binary>{Parser::parse(*pe_file)};
  } catch (const LIEF::exception& e) {
    WARN("Can't parse: '" << *pe_file << "' (" << e.what() << ")");
    return;
  }



  SECTION("DosHeader") {
    const DosHeader& dos_header_lhs = binary_lhs->dos_header();
    DosHeader dos_header_rhs = dos_header_lhs;
    REQUIRE(dos_header_lhs == dos_header_rhs);

    dos_header_rhs.file_size_in_pages(123);
    REQUIRE(dos_header_lhs != dos_header_rhs);
  }

  SECTION("Header") {
    const Header& header_lhs = binary_lhs->header();
    Header header_rhs = header_lhs;
    REQUIRE(header_lhs == header_rhs);

    header_rhs.sizeof_optional_header(456);
    REQUIRE(header_lhs != header_rhs);
  }

  SECTION("OptionalHeader") {
    const OptionalHeader& optional_header_lhs = binary_lhs->optional_header();
    OptionalHeader optional_header_rhs = optional_header_lhs;
    REQUIRE(optional_header_lhs == optional_header_rhs);

    optional_header_rhs.addressof_entrypoint(0xDEADBEEF);
    REQUIRE(optional_header_lhs != optional_header_rhs);
  }

  SECTION("Sections") {
    for (const Section& section_lhs : binary_lhs->sections()) {
      Section section_rhs = section_lhs;
      REQUIRE(section_lhs == section_rhs);

      section_rhs.name("toto");
      REQUIRE(section_lhs != section_rhs);
    }
  }

  SECTION("Data Directories") {
    for (size_t i = 0; i < binary_lhs->data_directories().size(); ++i) {
      REQUIRE(binary_lhs->data_directories()[i] == binary_rhs->data_directories()[i]);
    }
  }

  SECTION("Imports") {
    if (not binary_lhs->has_imports()) {
      return;
    }
    for (const Import& import_lhs : binary_lhs->imports()) {
      const Import& import_rhs = import_lhs;
      REQUIRE(import_lhs == import_rhs);
    }
  }

  SECTION("Relocations") {
    if (not binary_lhs->has_relocations()) {
      return;
    }

    for (const Relocation& relocation_lhs : binary_lhs->relocations()) {
      Relocation relocation_rhs = relocation_lhs;
      REQUIRE(relocation_lhs == relocation_rhs);

      relocation_rhs.virtual_address(123);
      REQUIRE(relocation_lhs != relocation_rhs);

    }
  }


  SECTION("Exports") {
    if (not binary_lhs->has_exports()) {
      return;
    }

    const Export& export_lhs = binary_lhs->get_export();
    const Export& export_rhs = binary_rhs->get_export();

    REQUIRE(export_lhs == export_rhs);
  }


  SECTION("TLS") {
    if (not binary_lhs->has_tls()) {
      return;
    }

    const TLS& tls_lhs = binary_lhs->tls();
    const TLS& tls_rhs = binary_rhs->tls();
    REQUIRE(tls_lhs == tls_rhs);

  }





}
