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

using namespace LIEF::ELF;

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <ELF binary>" << '\n';
    return EXIT_FAILURE;
  }

  if (!is_elf(argv[1])) {
    std::cerr << argv[1] << " is not a ELF file. Abort !" << '\n';
    return EXIT_FAILURE;
  }

  std::unique_ptr<const Binary> binary{Parser::parse(argv[1])};

  std::cout << "== Exported Symbols ==" << '\n';
  for (const Symbol& symbol : binary->exported_symbols()) {
    std::cout << symbol << '\n';
  }
  std::cout << "== Imported Symbols ==" << '\n';
  for (const Symbol& symbol : binary->imported_symbols()) {
    std::cout << symbol << '\n';
  }


  return 0;

}
