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
#include <LIEF/PE/hash.hpp>

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


  if (pe_file_str.find("PE32_x86_binary_KMSpico_setup_MALWARE.exe") != std::string::npos) {
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
  INFO("Output: " << output_name);

  binary_original.reset(Parser::parse(pe_file_str));
  std::unique_ptr<Binary> binary_built{Parser::parse(output_name)};

  SECTION("Checks functions") {
    //REQUIRE(binary_original->get_virtual_size() == binary_original->optional_header().sizeof_image());
    //REQUIRE(binary_original->get_sizeof_headers() == binary_original->optional_header().sizeof_headers());

    //REQUIRE(binary_built->get_virtual_size() == binary_built->optional_header().sizeof_image());
    //REQUIRE(binary_built->get_sizeof_headers() == binary_built->optional_header().sizeof_headers());
  }

  SECTION("Dos Header") {
    REQUIRE(binary_original->dos_header() == binary_built->dos_header());
  }


  SECTION("Header") {
    const Header& header_lhs = binary_original->header();
    const Header& header_rhs = binary_built->header();
    REQUIRE(header_lhs.signature() == header_rhs.signature());
    REQUIRE(header_lhs.machine() == header_rhs.machine());
    REQUIRE(header_lhs.time_date_stamp() == header_rhs.time_date_stamp());
    REQUIRE(header_lhs.characteristics() == header_rhs.characteristics());
  }


  SECTION("Optional Header") {
    const OptionalHeader& header_lhs = binary_original->optional_header();
    const OptionalHeader& header_rhs = binary_built->optional_header();

    REQUIRE(header_lhs.magic() == header_rhs.magic());
    REQUIRE(header_lhs.major_linker_version() == header_rhs.major_linker_version());
    REQUIRE(header_lhs.minor_linker_version() == header_rhs.minor_linker_version());
    REQUIRE(header_lhs.addressof_entrypoint() == header_rhs.addressof_entrypoint());
    REQUIRE(header_lhs.baseof_code() == header_rhs.baseof_code());
    REQUIRE(header_lhs.imagebase() == header_rhs.imagebase());
    REQUIRE(header_lhs.section_alignment() == header_rhs.section_alignment());
    REQUIRE(header_lhs.file_alignment() == header_rhs.file_alignment());
    REQUIRE(header_lhs.major_operating_system_version() == header_rhs.major_operating_system_version());
    REQUIRE(header_lhs.minor_operating_system_version() == header_rhs.minor_operating_system_version());
    REQUIRE(header_lhs.major_image_version() == header_rhs.major_image_version());
    REQUIRE(header_lhs.minor_image_version() == header_rhs.minor_image_version());
    REQUIRE(header_lhs.major_subsystem_version() == header_rhs.major_subsystem_version());
    REQUIRE(header_lhs.minor_subsystem_version() == header_rhs.minor_subsystem_version());
    REQUIRE(header_lhs.win32_version_value() == header_rhs.win32_version_value());
    REQUIRE(header_lhs.subsystem() == header_rhs.subsystem());
    REQUIRE(header_lhs.dll_characteristics() == header_rhs.dll_characteristics());
    REQUIRE(header_lhs.loader_flags() == header_rhs.loader_flags());
    REQUIRE(header_lhs.numberof_rva_and_size() == header_rhs.numberof_rva_and_size());
  }

  SECTION("Section") {

    for (const Section& section_lhs : binary_original->sections()) {

      INFO("Section " << section_lhs.name());
      const Section& section_rhs = binary_built->get_section(section_lhs.name());
      INFO("RHS" << section_rhs);
      INFO("LHS" << section_lhs);
      REQUIRE(section_lhs.name()                      == section_rhs.name());
      REQUIRE(section_lhs.virtual_size()              == section_rhs.virtual_size());
      REQUIRE(section_lhs.virtual_address()           == section_rhs.virtual_address());
      REQUIRE(section_lhs.size()                      == section_rhs.size());
      REQUIRE(section_lhs.offset()                    == section_rhs.offset());
      REQUIRE(section_lhs.pointerto_relocation()      == section_rhs.pointerto_relocation());
      REQUIRE(section_lhs.content().size()            == section_rhs.content().size());
      //REQUIRE(LIEF::Hash::hash(section_lhs.content()) == LIEF::Hash::hash(section_rhs.content()));
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
    REQUIRE(binary_original->debug() == binary_built->debug());
  }


  SECTION("Resources") {
    if (not binary_original->has_resources()) {
      return;
    }
    const ResourceNode& root_lhs = binary_original->resources();
    const ResourceNode& root_rhs = binary_built->resources();
    INFO("LHS: " << binary_original->resources_manager());
    INFO("RHS: " << binary_built->resources_manager());
    //REQUIRE(root_lhs == root_rhs);
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
