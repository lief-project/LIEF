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
#include <LIEF/visitors/Hash.hpp>

#include "utils.hpp"

extern const YAML::Node config = YAML::LoadFile(std::string(PATH_TO_CONFIG) + "/config.yaml");

using namespace LIEF::PE;

TEST_CASE("Test parse", "[pe][builder]")
{

  using namespace Catch::Generators;
  std::vector<std::string> pe_files = Test::get_pe_files();

  // Get one
  std::vector<std::string>::iterator pe_file = between(
      std::begin(pe_files),
      std::prev(std::end(pe_files)));
  const std::string& pe_file_str = *pe_file;

  if (pe_file_str.find("winenotepad.exe") != std::string::npos) {
    return;
  }

  if (pe_file_str.find("PE32_x86_binary_winhello-mingw.exe") != std::string::npos) {
    return;
  }

  INFO("Binary used: " << pe_file_str);

  std::unique_ptr<Binary> binary_original;
  try {
     binary_original = std::unique_ptr<Binary>{Parser::parse(pe_file_str)};
  } catch (const LIEF::exception& e) {
    WARN("Can't parse: '" << pe_file_str << "' (" << e.what() << ")");
    return;
  }

  std::string output_name = binary_original->name() + "_built";

  Builder builder{binary_original.get()};

  builder.
    build_imports(true).
    patch_imports(true).
    build_relocations(true).
    build_tls(true).
    build_resources(true);
  try {
    builder.build();
  } catch (const LIEF::exception& e) {
    FAIL("Can't build: '" << pe_file_str << "' (" << e.what() << ")");
    return;
  }
  builder.write(output_name);

  std::unique_ptr<Binary> binary_built{Parser::parse(output_name)};

  SECTION("Checks functions") {
    REQUIRE(binary_original->get_virtual_size() == binary_original->optional_header().sizeof_image());
    REQUIRE(binary_original->get_sizeof_headers() == binary_original->optional_header().sizeof_headers());

    REQUIRE(binary_original->get_virtual_size() == binary_original->optional_header().sizeof_image());
    REQUIRE(binary_original->get_sizeof_headers() == binary_original->optional_header().sizeof_headers());
  }

  SECTION("Dos Header") {
    REQUIRE(binary_original->dos_header() == binary_built->dos_header());
  }


  SECTION("Header") {
    REQUIRE(binary_original->header() == binary_built->header());
  }


  SECTION("Optional Header") {
    REQUIRE(binary_original->optional_header() == binary_built->optional_header());
  }

  SECTION("Section") {

    for (const Section& section_lhs : binary_original->get_sections()) {

      INFO("Section " << section_lhs.name());
      const Section& section_rhs = binary_built->get_section(section_lhs.name());
      REQUIRE(section_lhs.name() == section_rhs.name());
      REQUIRE(section_lhs.virtual_size() == section_rhs.virtual_size());
      REQUIRE(section_lhs.virtual_address() == section_rhs.virtual_address());
      REQUIRE(section_lhs.size() == section_rhs.size());
      REQUIRE(section_lhs.offset() == section_rhs.offset());
      REQUIRE(section_lhs.pointerto_relocation() == section_rhs.pointerto_relocation());
      REQUIRE(LIEF::Hash::hash(section_lhs.content()) == LIEF::Hash::hash(section_rhs.content()));
    }


  }

  SECTION("TLS") {
    const TLS& tls_lhs = binary_original->tls();
    const TLS& tls_rhs = binary_built->tls();
    REQUIRE(tls_lhs.callbacks()           == tls_rhs.callbacks());
    REQUIRE(tls_lhs.addressof_raw_data()  == tls_rhs.addressof_raw_data());
    REQUIRE(tls_lhs.addressof_index()     == tls_rhs.addressof_index());
    REQUIRE(tls_lhs.addressof_callbacks() == tls_rhs.addressof_callbacks());
    REQUIRE(tls_lhs.sizeof_zero_fill()    == tls_rhs.sizeof_zero_fill());
    REQUIRE(tls_lhs.characteristics()     == tls_rhs.characteristics());
    REQUIRE(tls_lhs.data_template()       == tls_rhs.data_template());
  }


  SECTION("Debug") {
    REQUIRE(binary_original->get_debug() == binary_built->get_debug());
  }


  SECTION("Resources") {
    if (not binary_original->has_resources()) {
      return;
    }
    const ResourceNode& root_lhs = binary_original->get_resources();
    const ResourceNode& root_rhs = binary_built->get_resources();

    REQUIRE(root_lhs == root_rhs);
  }

  SECTION("Relocations") {

    if (not binary_original->has_relocations()) {
      return;
    }

    it_relocations relocations_lhs = binary_original->relocations();
    it_relocations relocations_rhs = binary_built->relocations();
    REQUIRE(relocations_lhs.size() == relocations_rhs.size());

    for (size_t i = 0; i < relocations_lhs.size(); ++i) {
      REQUIRE(relocations_lhs[i] == relocations_rhs[i]);
    }
  }


  SECTION("Imports") {
    if (not binary_original->has_imports()) {
      return;
    }

    it_imports imports_lhs = binary_original->imports();
    it_imports imports_rhs = binary_built->imports();
    REQUIRE(imports_lhs.size() == imports_rhs.size());

    for (size_t i = 0; i < imports_lhs.size(); ++i) {
      REQUIRE(imports_lhs[i].name() == imports_rhs[i].name());
      REQUIRE(imports_lhs[i].forwarder_chain() == imports_rhs[i].forwarder_chain());
      REQUIRE(imports_lhs[i].timedatestamp() == imports_rhs[i].timedatestamp());

      it_import_entries entries_lhs = imports_lhs[i].entries();
      it_import_entries entries_rhs = imports_rhs[i].entries();
      REQUIRE(entries_lhs.size() == entries_rhs.size());
      for (size_t j = 0; j < entries_lhs.size(); ++j) {
        REQUIRE(entries_lhs[j].is_ordinal() == entries_rhs[j].is_ordinal());

        if (entries_lhs[j].is_ordinal()) {
          REQUIRE(entries_lhs[j].ordinal() == entries_rhs[j].ordinal());
        } else {

          REQUIRE(entries_lhs[j].hint() == entries_rhs[j].hint());
          REQUIRE(entries_lhs[j].name() == entries_rhs[j].name());
        }
      }
    }


  }



}
