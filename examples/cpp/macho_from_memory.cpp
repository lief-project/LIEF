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
#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>
#include <mach-o/dyld.h>

#include <iostream>
#include <iomanip>

using namespace LIEF::MachO;

// Create a "fake" bss section
uint8_t data[0x4001];
static struct foo {
  uint64_t x[0x20];
} bar;

uintptr_t get_module_base_address(const std::string& name) {
  const size_t nb_images = _dyld_image_count();
  for (size_t i = 0; i < nb_images; ++i) {
    std::string image_name = _dyld_get_image_name(i);
    std::cout << "Image at index #" << i << " :" << image_name << "\n";
    if (image_name.find(name) != std::string::npos) {
      return reinterpret_cast<uintptr_t>(_dyld_get_image_header(i));
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  LIEF::logging::set_level(LIEF::logging::LEVEL::DEBUG);

  //const uintptr_t base = get_module_base_address("macho_from_memory");
  const uintptr_t base = get_module_base_address("in_mem.test");
  if (base == 0) {
    return EXIT_FAILURE;
  }
  for (size_t i = 0; i < 234; ++i) {
    data[i] = base & 0xFF;
  }
  bar.x[0] = 1;
  memset(data, 0x4001, 1);

  std::cout << "Base address: 0x" << std::hex << base << "\n";
  std::unique_ptr<FatBinary> binaries = Parser::parse_from_memory(base);
  if (binaries == nullptr || binaries->empty()) {
    std::cerr << "Parsing failed" << '\n';
  }
  std::cout << "Parsing Done!" << "\n";
  for (Binary& bin : *binaries) {
    bin.write("/tmp/mem_rewrite.bin");
  }
  return EXIT_SUCCESS;
}

