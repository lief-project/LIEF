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
#include <iostream>
#include <memory>

#include <LIEF/ELF.hpp>

using namespace LIEF::ELF;

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <ELF binary>" << std::endl;
    return EXIT_FAILURE;
  }


  std::unique_ptr<const Binary> binary;
  try {
    binary = std::unique_ptr<const Binary>{Parser::parse(argv[1])};
  } catch (const LIEF::exception& e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "Binary: " << binary->name() << std::endl;
  std::cout << "== Header ==" << std::endl;
  std::cout << binary->get_header() << std::endl;

  std::cout << "== Sections ==" << std::endl;
  for (const Section& section : binary->get_sections()) {
    std::cout << section << std::endl;
  }
  std::cout << std::endl;

  std::cout << "== Segments ==" << std::endl;
  for (const Segment& segment : binary->get_segments()) {
    std::cout << segment << std::endl;
  }
  std::cout << std::endl;

  std::cout << "== Dynamic entries ==" << std::endl;
  for (const DynamicEntry& entry : binary->get_dynamic_entries()) {
    std::cout << entry << std::endl;
  }

  auto&& static_symbols = binary->get_static_symbols();
  if (static_symbols.size() > 0) {
    std::cout << "== Static symbols ==" << std::endl;
    for (const Symbol& symbol : static_symbols) {
      std::cout << symbol << std::endl;
    }
  }

  std::cout << "== Dynamics symbols ==" << std::endl;
  for (const Symbol& symbol : binary->get_dynamic_symbols()) {
    std::cout << symbol << std::endl;
  }

  std::cout << "== Exported symbols ==" << std::endl;
  for (const Symbol& symbol : binary->get_exported_symbols()) {
    std::cout << symbol << std::endl;
  }


  std::cout << "== Imported symbols ==" << std::endl;
  for (const Symbol& symbol : binary->get_imported_symbols()) {
    std::cout << symbol << std::endl;
  }


  std::cout << "== Dynamic Relocations ==" << std::endl;
  for (const Relocation& relocation : binary->get_dynamic_relocations()) {
    std::cout << relocation << std::endl;
  }

  std::cout << "== PLT/GOT Relocations ==" << std::endl;
  for (const Relocation& relocation : binary->get_pltgot_relocations()) {
    std::cout << relocation << std::endl;
  }


  std::cout << "== GNU Hash ==" << std::endl;
  std::cout << binary->get_gnu_hash() << std::endl;



  //std::cout << "== Symbol Version ==" << std::endl;
  //std::vector<SymbolVersion>* symbolsVersion = binary->get_symbol_version();
  //for (const auto &symVersion : *symbolsVersion) {
  //  std::cout << symVersion << std::endl;
  //}


  //std::cout << "== Symbols Version Requirement ==" << std::endl;
  //std::vector<SymbolVersionRequirement> *symR = binary->get_symbol_version_requirement();
  //for (SymbolVersionRequirement &symbolR : *symR) {
  //  std::cout << symbolR << std::endl << std::endl;
  //  auto symAux = symbolR.get_auxiliary_symbols();
  //  for (auto &symbolAux : symAux) {
  //    std::cout << *symbolAux << std::endl;
  //  }
  //  std::cout << std::endl;
  //}

  return 0;

}
