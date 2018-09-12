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

#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/Abstract/Parser.hpp>

int main(int argc, char **argv) {
  std::cout << "Abstract Reader" << std::endl;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
    return -1;
  }

  std::unique_ptr<const LIEF::Binary> binary{LIEF::Parser::parse(argv[1])};

  std::cout << "== Header ==" << std::endl;
  std::cout << binary->header() << std::endl;

  std::cout << "== Sections ==" << std::endl;
  for (const LIEF::Section& s : binary->sections()) {
    std::cout << s << std::endl;
  }

  std::cout << "== Symbols ==" << std::endl;
  for (const LIEF::Symbol& s : binary->symbols()) {
    std::cout << s << std::endl;
  }

  std::cout << "== Exported functions ==" << std::endl;
  for(const LIEF::Function& func : binary->exported_functions()) {
    std::cout << func << std::endl;
  }

  std::cout << "== Imported functions ==" << std::endl;
  for(const LIEF::Function& func : binary->imported_functions()) {
    std::cout << func << std::endl;
  }

  std::cout << "== Imported Libraries ==" << std::endl;
  for(const std::string& name : binary->imported_libraries()) {
    std::cout << name << std::endl;
  }

  std::cout << "== Relocation ==" << std::endl;
  for(const LIEF::Relocation& relocation : binary->relocations()) {
    std::cout << relocation << std::endl;
  }

  return 0;


}
