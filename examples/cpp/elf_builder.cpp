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
#include <fstream>
#include <algorithm>
#include <iterator>

#include <LIEF/logging.hpp>
#include <LIEF/ELF.hpp>

int main(int argc, char **argv) {
  std::cout << "ELF builder" << '\n';
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Input Binary> <Output Binary>" << '\n';
    return -1;
  }

  std::unique_ptr<LIEF::ELF::Binary> binary = LIEF::ELF::Parser::parse(argv[1]);
  LIEF::ELF::Segment seg;
  seg.type(LIEF::ELF::Segment::TYPE::LOAD);
  //seg.content(std::vector<uint8_t>(0x100));
  //binary->add(seg);
  LIEF::logging::set_level(LIEF::logging::LEVEL::DEBUG);
  //LIEF::logging::set_level(LIEF::logging::LEVEL::LOG_WARN);
  //binary->get(LIEF::ELF::SEGMENT_TYPES::PT_GNU_RELRO).type(LIEF::ELF::SEGMENT_TYPES::PT_NULL);
  LIEF::ELF::Builder builder{*binary};
  LIEF::ELF::Builder::config_t config;
  config.force_relocate = true;

  builder.set_config(config);
  builder.build();
  builder.write(argv[2]);

  //binary->write(argv[2]);

  return 0;
}
