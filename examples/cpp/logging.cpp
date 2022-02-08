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
#include <iostream>
#include <memory>

#include <LIEF/LIEF.hpp>

int main(int argc, char **argv) {
  std::cout << "Abstract Reader" << '\n';
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << '\n';
    return -1;
  }

  std::cout << "Parsing with DEBUG level" << '\n';
  std::cout << "========================" << '\n';

  LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_DEBUG);
  std::unique_ptr<const LIEF::Binary> binary_global = LIEF::Parser::parse(argv[1]);

  // Disable logger
  LIEF::logging::disable();
  std::unique_ptr<const LIEF::Binary> binary_debug = LIEF::Parser::parse(argv[1]);

  return 0;
}
