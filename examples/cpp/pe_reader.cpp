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

#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>

using namespace LIEF::PE;

int main(int argc, char **argv) {
  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_DEBUG);
  std::cout << "PE Reader" << std::endl;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <PE binary>" << std::endl;
    return -1;
  }

  std::unique_ptr<const Binary> binary{Parser::parse(argv[1])};

  std::cout << "== Dos Header ==" << std::endl;
  std::cout << binary->dos_header() << std::endl;

  std::cout << "== Header ==" << std::endl;
  std::cout << binary->header() << std::endl;

  std::cout << "== Optional Header ==" << std::endl;
  std::cout << binary->optional_header() << std::endl;

  if (binary->has_rich_header()) {
    std::cout << "== Rich Header ==" << std::endl;
    std::cout << binary->rich_header() << std::endl;
  }

  std::cout << "== Data Directories ==" << std::endl;
  for (const DataDirectory& directory : binary->data_directories()) {
    std::cout << directory << std::endl;
  }

  std::cout << "== Sections ==" << std::endl;
  for (const Section& section : binary->sections()) {
    std::cout << section << std::endl;
  }

  if (binary->imports().size() > 0) {
    std::cout << "== Imports ==" << std::endl;
    for (const Import& import : binary->imports()) {
      std::cout << import << std::endl;
    }
  }

  if (binary->relocations().size() > 0) {
    std::cout << "== Relocations ==" << std::endl;
    for (const Relocation& relocation : binary->relocations()) {
      std::cout << relocation << std::endl;
    }
  }

  if (binary->has_tls()) {
    std::cout << "== TLS ==" << std::endl;
    std::cout << binary->tls() << std::endl;
  }

  if (binary->has_exports()) {
    std::cout << "== Exports ==" << std::endl;
    std::cout << binary->get_export() << std::endl;
  }

  if (binary->symbols().size() > 0) {
    std::cout << "== Symbols ==" << std::endl;
    for (const Symbol& symbol : binary->symbols()) {
      std::cout << symbol << std::endl;
    }
  }


  if (binary->has_debug()) {
    std::cout << "== Debug ==" << std::endl;
    for (const Debug& debug : binary->debug()) {
      std::cout << debug << std::endl;
    }
  }


  if (binary->has_resources()) {
    std::cout << "== Resources ==" << std::endl;
    std::cout << binary->resources_manager() << std::endl;
  }


  if (binary->has_signature()) {
    std::cout << "== Signature ==" << std::endl;
    std::cout << binary->signature() << std::endl;
  }



  return 0;
}
