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

#include <LIEF/LIEF.hpp>

int main(int argc, char **argv) {
  std::cout << "Abstract Reader" << std::endl;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
    return -1;
  }

  std::cout << "Parsing with Global level" << std::endl;
  std::cout << "=========================" << std::endl;

  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_GLOBAL);
  std::unique_ptr<const LIEF::Binary> binary_global{LIEF::Parser::parse(argv[1])};

  std::cout << "Parsing with Debug level" << std::endl;
  std::cout << "========================" << std::endl;

  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_DEBUG);
  std::unique_ptr<const LIEF::Binary> binary_debug{LIEF::Parser::parse(argv[1])};

  return 0;
}
