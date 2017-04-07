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
#include <pybind11/stl_bind.h>

#include "pyMachO.hpp"

//
// MachO modules
//
void init_MachO_module(py::module& m) {
  py::module LIEF_MachO_module = m.def_submodule("MachO", "Python API for MachO");

  py::bind_vector<std::vector<Binary*>>(m, "macho_list");

  // Objects
  init_MachO_Parser_class(LIEF_MachO_module);
  init_MachO_Binary_class(LIEF_MachO_module);
  init_MachO_Header_class(LIEF_MachO_module);
  init_MachO_LoadCommand_class(LIEF_MachO_module);
  init_MachO_DylibCommand_class(LIEF_MachO_module);
  init_MachO_SegmentCommand_class(LIEF_MachO_module);
  init_MachO_Section_class(LIEF_MachO_module);
  init_MachO_Symbol_class(LIEF_MachO_module);
  init_MachO_EncryptionInfoCommand_class(LIEF_MachO_module);


  // Enums
  init_MachO_Structures_enum(LIEF_MachO_module);
}
