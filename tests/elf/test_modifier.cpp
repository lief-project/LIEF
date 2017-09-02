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


TEST_CASE("Test remove dynamic symbol", "[elf][modifier][symbol][dynamic]")
{

  using namespace Catch::Generators;
  std::vector<std::string> elf_files = Test::get_elf_files();

  // Get one
  std::vector<std::string>::iterator elf_file = between(
      std::begin(elf_files),
      std::prev(std::end(elf_files)));

  const std::string& elf_file_str = *elf_file;


  //if (elf_file_str.find("systemd-resolve.bin") == std::string::npos) {
  if (elf_file_str.find("binary_tiny") != std::string::npos) {
    INFO("Skip " << elf_file_str);
    return;
  }

  if (elf_file_str.find("ELF64_x86-64_binary_rvs.bin") != std::string::npos) {
    INFO("Skip " << elf_file_str);
    return;
  }

  INFO("Binary used: " << elf_file_str);

  std::unique_ptr<Binary> binary = std::unique_ptr<Binary>{Parser::parse(elf_file_str)};
  it_symbols dynamic_symbols = binary->dynamic_symbols();

  auto&& it_symbol = std::find_if(
      std::begin(dynamic_symbols),
      std::end(dynamic_symbols),
      [] (const Symbol& symbol) {
        return symbol.name().length() > 2;
      });

  if (it_symbol == std::end(dynamic_symbols)) {
    return;
  }

  auto&& it_symbol_bis = std::find_if(
      std::begin(dynamic_symbols),
      std::end(dynamic_symbols),
      [&it_symbol] (const Symbol& symbol) {
        return symbol.name().length() > 2 and *it_symbol != symbol;
      });

  if (it_symbol_bis == std::end(dynamic_symbols)) {
    return;
  }



  const std::string symbol_removed_name     = it_symbol->name();
  const std::string symbol_bis_removed_name = it_symbol_bis->name();

  INFO("Symbol that will be removed: " << symbol_removed_name << " and " << symbol_bis_removed_name);

  Symbol* symbol = &(*it_symbol);

  binary->remove_dynamic_symbol(symbol);
  binary->remove_dynamic_symbol(symbol_bis_removed_name);

  std::string output_name = binary->name() + "_test_remove_symbol";
  binary->write(output_name);

  std::unique_ptr<Binary> binary_updated = std::unique_ptr<Binary>{Parser::parse(output_name)};
  dynamic_symbols = binary_updated->dynamic_symbols();
  it_symbol = std::find_if(
      std::begin(dynamic_symbols),
      std::end(dynamic_symbols),
      [&symbol_removed_name] (const Symbol& symbol) {
        return symbol.name() == symbol_removed_name;
      });

  it_symbol_bis = std::find_if(
      std::begin(dynamic_symbols),
      std::end(dynamic_symbols),
      [&symbol_bis_removed_name] (const Symbol& symbol) {
        return symbol.name() == symbol_bis_removed_name;
      });


  REQUIRE(it_symbol == std::end(dynamic_symbols));
  REQUIRE(it_symbol_bis == std::end(dynamic_symbols));

}


