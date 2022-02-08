/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
//
// Description
// ===========
// The tool is used to test the rebuilding of a binary.
// It take a binary as first argument, decompose it, rebuild the binary and then
// save it (second argument)
//

#include <iostream>
#include <memory>
#include <fstream>
#include <algorithm>
#include <iterator>

#include <LIEF/MachO.hpp>

using namespace LIEF;

int main(int argc, char **argv) {
  std::cout << "MachO Rebuilder" << '\n';
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Input Binary> <Output Binary>" << "\n";
    return 1;
  }

  std::unique_ptr<LIEF::MachO::FatBinary> fat = MachO::Parser::parse(argv[1]);
  MachO::Binary* binary = fat->back();
  if (binary == nullptr) {
    std::cerr << "Can't access binary" << "\n";
    return 1;
  }
  binary->write(argv[2]);

  return 0;
}
