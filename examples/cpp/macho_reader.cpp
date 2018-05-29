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
#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>

#include <iostream>
#include <iomanip>

using namespace LIEF::MachO;

void print_binary(const Binary& binary) {
  std::cout << binary.header() << std::endl;

  std::cout << "== Library ==" << std::endl;
  for (const DylibCommand& library : binary.libraries()) {
    std::cout << library << std::endl;
  }
  std::cout << std::endl;

  std::cout << "== Sections ==" << std::endl;
  for (const Section& section : binary.sections()) {
    std::cout << section << std::endl;
  }

  //std::cout << "== Segments ==" << std::endl;

  //for (SegmentCommand& segment : binary.segments()) {
  //  std::cout << segment << std::endl;
  //  if (segment.sections().size() > 0) {
  //    //std::cout << std::hex;
  //    //std::cout << std::left
  //    // << std::setw(20) << "Name"
  //    // << std::setw(17) << "Segment Name"
  //    // << std::setw(10) << "Address"
  //    // << std::setw(10) << "Size"
  //    // << std::setw(10) << "Offset"
  //    // << std::setw(10) << "Alignment"
  //    // << std::setw(20) << "Relocation offset"
  //    // << std::setw(20) << "Nb relocations"
  //    // << std::setw(10) << "Flags"
  //    // << std::setw(10) << "Reserved 1"
  //    // << std::setw(10) << "Reserved 2"
  //    // << std::setw(10) << "Reserved 3" << std::endl;
  //    for (Section& section : segment.sections()) {
  //      std::cout << " * " << section << std::endl;
  //      auto content = section.content();
  //    }
  //  }
  //}
  //std::cout << std::endl;

  //auto commands = binary.commands();
  for (const LoadCommand& cmd : binary.commands()) {
    std::cout << cmd << std::endl;
    std::cout << "======================" << std::endl;
  }

  std::cout << "== Symbols ==" << std::endl;
  for (const Symbol& symbol : binary.symbols()) {
    std::cout << symbol << std::endl;
  }


  std::cout << "== Exported symbols ==" << std::endl;
  for (const Symbol& symbol : binary.exported_symbols()) {
    std::cout << symbol << std::endl;
  }

  std::cout << "== Imported symbols ==" << std::endl;
  for (const Symbol& symbol : binary.imported_symbols()) {
    std::cout << symbol << std::endl;
  }


  std::cout << "== Relocations ==" << std::endl;
  for (const Relocation& relocation : binary.relocations()) {
    std::cout << relocation << std::endl;
  }



}

int main(int argc, char **argv) {
  LIEF::Logger::set_level(LIEF::LOGGING_LEVEL::LOG_DEBUG);
  std::cout << "MachO Reader" << std::endl;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <MachO binary>" << std::endl;
    return -1;
  }
  std::unique_ptr<FatBinary> binaries{Parser::parse(argv[1])};
  for (const Binary& binary : *binaries) {
    print_binary(binary);
    std::cout << std::endl;
  }

  return 0;
}

