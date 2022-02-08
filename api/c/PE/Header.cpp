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
#include "Header.hpp"

namespace LIEF {
namespace PE {

void init_c_header(Pe_Binary_t* c_binary, Binary* binary) {

  const Header& header = binary->header();

  const Header::signature_t& signature = header.signature();

  c_binary->header.machine                = static_cast<enum LIEF_PE_MACHINE_TYPES>(header.machine());
  c_binary->header.numberof_sections      = header.numberof_sections();
  c_binary->header.time_date_stamp        = header.time_date_stamp();
  c_binary->header.pointerto_symbol_table = header.pointerto_symbol_table();
  c_binary->header.numberof_symbols       = header.numberof_symbols();
  c_binary->header.sizeof_optional_header = header.sizeof_optional_header();
  c_binary->header.characteristics        = static_cast<uint16_t>(header.characteristics());

  std::copy(
      std::begin(signature),
      std::end(signature),
      c_binary->header.signature);
}

}
}
