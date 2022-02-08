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
#include "LIEF/MachO/Binary.h"

#include "LIEF/MachO/Binary.hpp"

#include "Binary.hpp"
#include "Section.hpp"
#include "Header.hpp"
#include "Symbol.hpp"
#include "Segment.hpp"
#include "LoadCommand.hpp"


using namespace LIEF::MachO;

namespace LIEF {
namespace MachO {
void init_c_binary(Macho_Binary_t* c_binary, Binary* binary) {

  c_binary->handler = reinterpret_cast<void*>(binary);
  c_binary->name    = binary->name().c_str();
  c_binary->imagebase = binary->imagebase();
  init_c_header(c_binary, binary);
  init_c_commands(c_binary, binary);
  init_c_symbols(c_binary, binary);
  init_c_sections(c_binary, binary);
  init_c_segments(c_binary, binary);
}
}
}

void macho_binaries_destroy(Macho_Binary_t** binaries) {
  for (size_t i = 0; binaries[i] != nullptr; ++i) {
    destroy_sections(binaries[i]);
    destroy_commands(binaries[i]);
    destroy_symbols(binaries[i]);
    destroy_segments(binaries[i]);

    delete reinterpret_cast<Binary*>(binaries[i]->handler);
    free(binaries[i]);
  }
  free(binaries);

}
