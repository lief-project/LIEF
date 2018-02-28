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
#include "pyELF.hpp"

//
// ELF modules
//
void init_ELF_module(py::module& m) {
  py::module LIEF_ELF_module = m.def_submodule("ELF", "Python API for ELF");
  // Enums
  init_ELF_Structures_enum(LIEF_ELF_module);

  // Objects
  init_ELF_Parser_class(LIEF_ELF_module);
  init_ELF_SymbolVersion_class(LIEF_ELF_module);
  init_ELF_Binary_class(LIEF_ELF_module);
  init_ELF_Header_class(LIEF_ELF_module);
  init_ELF_Section_class(LIEF_ELF_module);
  init_ELF_Segment_class(LIEF_ELF_module);
  init_ELF_Symbol_class(LIEF_ELF_module);
  init_ELF_Relocation_class(LIEF_ELF_module);
  init_ELF_SymbolVersionAux_class(LIEF_ELF_module);
  init_ELF_SymbolVersionAuxRequirement_class(LIEF_ELF_module);
  init_ELF_SymbolVersionDefinition_class(LIEF_ELF_module);
  init_ELF_SymbolVersionRequirement_class(LIEF_ELF_module);
  init_ELF_DynamicEntry_class(LIEF_ELF_module);
  init_ELF_DynamicEntryLibrary_class(LIEF_ELF_module);
  init_ELF_DynamicSharedObject_class(LIEF_ELF_module);
  init_ELF_DynamicEntryArray_class(LIEF_ELF_module);
  init_ELF_DynamicEntryRpath_class(LIEF_ELF_module);
  init_ELF_DynamicEntryRunPath_class(LIEF_ELF_module);
  init_ELF_DynamicEntryFlags_class(LIEF_ELF_module);
  init_ELF_GnuHash_class(LIEF_ELF_module);
  init_ELF_SysvHash_class(LIEF_ELF_module);
  init_ELF_Builder_class(LIEF_ELF_module);
  init_ELF_Note_class(LIEF_ELF_module);
  init_ELF_AndroidNote_class(LIEF_ELF_module);

  py::module LIEF_ELF32_module = LIEF_ELF_module.def_submodule("ELF32", "");
  init_ELF32_sizes(LIEF_ELF32_module);

  py::module LIEF_ELF64_module = LIEF_ELF_module.def_submodule("ELF64", "");
  init_ELF64_sizes(LIEF_ELF64_module);
}
