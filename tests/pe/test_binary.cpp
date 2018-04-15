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

  std::string output_name = binary_original->name() + "_built_binary";

  Builder builder{binary_original.get()};

  builder.
    build_imports(true).
    patch_imports(false).
    build_relocations(false).
    build_tls(false).
    build_resources(false);

  try {
    builder.build();
  } catch (const LIEF::exception& e) {
    FAIL("Can't build: '" << pe_file_str << "' (" << e.what() << ")");
    return;
  }
  builder.write(output_name);

  std::unique_ptr<Binary> binary_built{Parser::parse(output_name)};

  binary_original = std::unique_ptr<Binary>{Parser::parse(pe_file_str)};

  SECTION("Imports") {
    if (not binary_original->has_imports()) {
      return;
    }

    it_imports imports_lhs = binary_original->imports();
    it_imports imports_rhs = binary_built->imports();

    for (size_t i = 0; i < imports_lhs.size(); ++i) {

      it_import_entries entries_lhs = imports_lhs[i].entries();
      it_import_entries entries_rhs = imports_rhs[i].entries();
      for (size_t j = 0; j < entries_lhs.size(); ++j) {
        if (not entries_lhs[j].is_ordinal()) {
          INFO("Library: " << imports_lhs[i].name() << ". Function: " << entries_lhs[j].name());
          uint64_t address = binary_original->predict_function_rva(imports_lhs[i].name(), entries_lhs[j].name());
          if (address > 0) {
            CHECK(address == entries_rhs[j].iat_address());
          }
        }
      }
    }


  }



}
