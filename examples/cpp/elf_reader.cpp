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
#include <iostream>
#include <memory>

#include <LIEF/ELF.hpp>
#include <LIEF/logging.hpp>


using namespace LIEF::ELF;

int main(int argc, char **argv) {

  LIEF::logging::set_level(LIEF::logging::LEVEL::DEBUG);
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <ELF binary>" << '\n';
    return EXIT_FAILURE;
  }


  std::unique_ptr<const Binary> binary = std::unique_ptr<const Binary>{Parser::parse(argv[1])};
  if (binary == nullptr) {
    return EXIT_FAILURE;
  }

  binary->functions();

  std::cout << "Binary: " << argv[1] << '\n';
  std::cout << "Interpreter: " << binary->interpreter() << '\n';
  std::cout << "== Header ==" << '\n';
  std::cout << binary->header() << '\n';

  std::cout << "== Sections ==" << '\n';
  for (const Section& section : binary->sections()) {
    std::cout << section << '\n';
  }
  std::cout << '\n';

  std::cout << "== Segments ==" << '\n';
  for (const Segment& segment : binary->segments()) {
    std::cout << segment << '\n';
  }
  std::cout << '\n';

  std::cout << "== Dynamic entries ==" << '\n';
  for (const DynamicEntry& entry : binary->dynamic_entries()) {
    std::cout << entry << '\n';
  }

  auto symtab_symbols = binary->symtab_symbols();
  if (symtab_symbols.size() > 0) {
    std::cout << "== .symtab (debug) symbols ==" << '\n';
    for (const Symbol& symbol : symtab_symbols) {
      std::cout << symbol << '\n';
    }
  }

  std::cout << "== Dynamics symbols ==" << '\n';
  for (const Symbol& symbol : binary->dynamic_symbols()) {
    std::cout << symbol << '\n';
  }

  std::cout << "== Exported symbols ==" << '\n';
  for (const Symbol& symbol : binary->exported_symbols()) {
    std::cout << symbol << '\n';
  }


  std::cout << "== Imported symbols ==" << '\n';
  for (const Symbol& symbol : binary->imported_symbols()) {
    std::cout << symbol << '\n';
  }


  std::cout << "== Dynamic Relocations ==" << '\n';
  for (const Relocation& relocation : binary->dynamic_relocations()) {
    std::cout << relocation << '\n';
  }

  std::cout << "== PLT/GOT Relocations ==" << '\n';
  for (const Relocation& relocation : binary->pltgot_relocations()) {
    std::cout << relocation << '\n';
  }


  if (binary->use_gnu_hash()) {
    std::cout << "== GNU Hash ==" << '\n';
    std::cout << binary->gnu_hash() << '\n';
  }


  if (binary->use_sysv_hash()) {
    std::cout << "== SYSV Hash ==" << '\n';
    std::cout << binary->sysv_hash() << '\n';
  }

  if (binary->notes().size() > 0) {
    std::cout << "== Notes ==" << '\n';

    for (const Note& note : binary->notes()) {
      std::cout << note << '\n';
    }
  }

  return 0;

}
