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
#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>

#include <iostream>

using namespace LIEF::MachO;

void print_binary(const Binary& binary) {
  std::cout << binary.header() << '\n';

  std::cout << "== Library ==" << '\n';
  for (const DylibCommand& library : binary.libraries()) {
    std::cout << library << '\n';
  }
  std::cout << '\n';

  std::cout << "== Sections ==" << '\n';
  for (const Section& section : binary.sections()) {
    std::cout << section << '\n';
  }

  for (const LoadCommand& cmd : binary.commands()) {
    std::cout << cmd << '\n';
    std::cout << "======================" << '\n';
  }

  std::cout << "== Symbols ==" << '\n';
  for (const Symbol& symbol : binary.symbols()) {
    std::cout << symbol << '\n';
  }


  std::cout << "== Exported symbols ==" << '\n';
  for (const Symbol& symbol : binary.exported_symbols()) {
    std::cout << symbol << '\n';
  }

  std::cout << "== Imported symbols ==" << '\n';
  for (const Symbol& symbol : binary.imported_symbols()) {
    std::cout << symbol << '\n';
  }


  std::cout << "== Relocations ==" << '\n';
  for (const Relocation& relocation : binary.relocations()) {
    std::cout << relocation << '\n';
  }

}

int main(int argc, char **argv) {
  LIEF::logging::set_level(LIEF::logging::LEVEL::DEBUG);
  std::cout << "MachO Reader" << '\n';
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <MachO binary>" << '\n';
    return -1;
  }
  std::unique_ptr<FatBinary> binaries = Parser::parse(argv[1]);

  for (const Binary& binary : *binaries) {
    print_binary(binary);
    std::cout << '\n';
  }

  return 0;
}

