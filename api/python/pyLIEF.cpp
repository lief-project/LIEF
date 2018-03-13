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
#include "LIEF/logging.hpp"
#include "LIEF/version.h"
#include "pyLIEF.hpp"

py::module LIEF_module("_pylief", "Python API for LIEF");

PYBIND11_MODULE(_pylief, LIEF_module) {


  LIEF_module.attr("__version__") = py::str(LIEF_VERSION);
  init_LIEF_Object_class(LIEF_module);

  init_LIEF_iterators(LIEF_module);

  init_LIEF_Logger(LIEF_module);

  // Init custom LIEF exceptions
  init_LIEF_exceptions(LIEF_module);

  // Init the LIEF module
  init_LIEF_module(LIEF_module);


  // Init the ELF module
#if defined(LIEF_ELF_SUPPORT)
  init_ELF_module(LIEF_module);
#endif

  // Init the PE module
#if defined(LIEF_PE_SUPPORT)
  init_PE_module(LIEF_module);
#endif

  // Init the MachO  module
#if defined(LIEF_MACHO_SUPPORT)
  init_MachO_module(LIEF_module);
#endif

  // Init util functions
  init_utils_functions(LIEF_module);


#if defined(LIEF_JSON_SUPPORT)
  init_json_functions(LIEF_module);
#endif

}
