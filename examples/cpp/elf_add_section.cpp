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
#include <iostream>

#include <LIEF/ELF.hpp>

using namespace LIEF::ELF;

int main(int argc, char **argv) {
  std::cout << "ELF Section rename" << '\n';
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << "<binary> <binary output name>" << '\n';
    return -1;
  }

  std::unique_ptr<Binary> binary = Parser::parse(argv[1]);
  for (size_t i = 0; i < 2; ++i) {
    Section new_section{".test"};
    std::vector<uint8_t> data(100, 0);
    new_section.content(std::move(data));
    binary->add(new_section);
  }
  binary->write(argv[2]);

  return 0;
}
