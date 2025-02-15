/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include <LIEF/PE.hpp>

using namespace LIEF::PE;
int main(int argc, char **argv) {
  std::cout << "PE Rebuilder" << '\n';
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Input Binary> <Output Binary>" << '\n';
    return EXIT_FAILURE;
  }

  std::unique_ptr<Binary> binary = Parser::parse(argv[1]);
  if (binary == nullptr) {
    return EXIT_FAILURE;
  }

  Builder::config_t config;
  binary->write(argv[2], config);
  return EXIT_SUCCESS;
}
