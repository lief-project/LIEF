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
#include <fstream>
#include <algorithm>
#include <iterator>

#include <LIEF/MachO.hpp>

using namespace LIEF;

int main(int argc, char **argv) {
  std::cout << "MachO Instrumentation" << std::endl;
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Input Binary> <Output Binary>" << std::endl;
    return -1;
  }

  std::unique_ptr<LIEF::MachO::FatBinary> binaries{MachO::Parser::parse(argv[1])};
  MachO::Binary& binary = binaries->back();
  auto&& segments = binary.segments();
  auto&& itSegment  = std::find_if(
      std::begin(segments),
      std::end(segments),
      [] (const MachO::SegmentCommand& segment) {
        return segment.name() == "__TEXT";
      });

  if (itSegment != std::end(segments) and (*itSegment).sections().size() > 0) {
    MachO::SegmentCommand& segment = (*itSegment);
    MachO::Section& section        = *segment.sections();
    //segment.remove_all_sections();
    //segment.virtual_address(0xdeadbeef);
    //segment.name("foo");
    //section.name("bar");
  }

  // Modify symbol's name
  //auto symbols = binary->symbols();
  //for (MachO::Symbol& symbol : symbols) {
  //  symbol.name("toto");
  //}


  std::string segment_name = "__TEXT";
  std::vector<uint8_t> payload(0x30, 0x33);

  MachO::segment_command_64 segment_header;
  std::copy(std::begin(segment_name), std::end(segment_name), segment_header.segname);
  segment_header.segname[segment_name.size()] = 0;
  segment_header.vmaddr   = 0x200050000;
  segment_header.vmsize   = 0x2000;
  segment_header.fileoff  = binary.original_size();
  segment_header.filesize = payload.size();
  segment_header.maxprot  = 7;
  segment_header.initprot = 3;
  segment_header.nsects   = 0;
  segment_header.flags    = 0;
  segment_header.cmdsize  = sizeof(segment_header);
  segment_header.cmd      = static_cast<uint32_t>(MachO::LOAD_COMMAND_TYPES::LC_SEGMENT_64);

  std::unique_ptr<MachO::LoadCommand> segment{ new MachO::SegmentCommand{&segment_header}};
  segment->size(sizeof(segment_header));
    static_cast<MachO::SegmentCommand*>(segment.get())->content(payload);

  segment->data({
      reinterpret_cast<uint8_t*>(&segment_header),
      reinterpret_cast<uint8_t*>(&segment_header) + sizeof(segment_header)
      });
  //binary->insert_command(std::move(segment));
  binary.write(argv[2]);


  return 0;
}
