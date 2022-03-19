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
#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include <iostream>
#include <memory>

using namespace LIEF::PE;

int main(int argc, char** argv) {
  LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_DEBUG);
  std::cout << "PE Reader" << '\n';
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <PE binary>" << '\n';
    return -1;
  }

  std::unique_ptr<const Binary> binary{Parser::parse(argv[1])};

  std::cout << "== Dos Header ==" << '\n';
  std::cout << binary->dos_header() << '\n';

  std::cout << "== Header ==" << '\n';
  std::cout << binary->header() << '\n';

  std::cout << "== Optional Header ==" << '\n';
  std::cout << binary->optional_header() << '\n';

  if (binary->has_rich_header()) {
    std::cout << "== Rich Header ==" << '\n';
    std::cout << binary->rich_header() << '\n';
  }

  std::cout << "== Data Directories ==" << '\n';
  for (const DataDirectory& directory : binary->data_directories()) {
    std::cout << directory << '\n';
  }

  std::cout << "== Sections ==" << '\n';
  for (const Section& section : binary->sections()) {
    std::cout << section << '\n';
  }

  if (binary->imports().size() > 0) {
    std::cout << "== Imports ==" << '\n';
    for (const Import& import : binary->imports()) {
      std::cout << import << '\n';
    }
  }

  if (binary->relocations().size() > 0) {
    std::cout << "== Relocations ==" << '\n';
    for (const Relocation& relocation : binary->relocations()) {
      std::cout << relocation << '\n';
    }
  }

  if (binary->has_tls()) {
    std::cout << "== TLS ==" << '\n';
    std::cout << binary->tls() << '\n';
  }

  if (binary->has_exports()) {
    std::cout << "== Exports ==" << '\n';
    std::cout << binary->get_export() << '\n';
  }

  if (!binary->symbols().empty()) {
    std::cout << "== Symbols ==" << '\n';
    for (const Symbol& symbol : binary->symbols()) {
      std::cout << symbol << '\n';
    }
  }

  if (binary->has_debug()) {
    std::cout << "== Debug ==" << '\n';
    for (const Debug& debug : binary->debug()) {
      std::cout << debug << '\n';
    }
  }

  if (binary->has_resources()) {
    std::cout << "== Resources ==" << '\n';
    std::cout << binary->resources_manager() << '\n';
  }

  for (const Signature& sig : binary->signatures()) {
    std::cout << "== Signature ==" << '\n';
    std::cout << sig << '\n';
  }

  return 0;
}
