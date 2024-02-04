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

#include <LIEF/Abstract.hpp>

int main(int argc, char **argv) {
  std::cout << "Abstract Reader" << '\n';
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << '\n';
    return -1;
  }

  std::unique_ptr<const LIEF::Binary> binary{LIEF::Parser::parse(argv[1])};

  std::cout << "== Header ==" << '\n';
  std::cout << binary->header() << '\n';

  std::cout << "== Sections ==" << '\n';
  for (const LIEF::Section& s : binary->sections()) {
    std::cout << s << '\n';
  }

  std::cout << "== Symbols ==" << '\n';
  for (const LIEF::Symbol& s : binary->symbols()) {
    std::cout << s << '\n';
  }

  std::cout << "== Exported functions ==" << '\n';
  for(const LIEF::Function& func : binary->exported_functions()) {
    std::cout << func << '\n';
  }

  std::cout << "== Imported functions ==" << '\n';
  for(const LIEF::Function& func : binary->imported_functions()) {
    std::cout << func << '\n';
  }

  std::cout << "== Imported Libraries ==" << '\n';
  for(const std::string& name : binary->imported_libraries()) {
    std::cout << name << '\n';
  }

  std::cout << "== Relocation ==" << '\n';
  for(const LIEF::Relocation& relocation : binary->relocations()) {
    std::cout << relocation << '\n';
  }

  return 0;


}
