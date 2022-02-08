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
#include "LIEF/logging.hpp"
#include "LIEF/version.h"
#include "pyLIEF.hpp"
#include "pyAbstract.hpp"

#if defined(LIEF_ELF_SUPPORT)
  #include "ELF/pyELF.hpp"
#endif

#if defined(LIEF_PE_SUPPORT)
  #include "PE/pyPE.hpp"
#endif

#if defined(LIEF_MACHO_SUPPORT)
  #include "MachO/pyMachO.hpp"
#endif

#if defined(LIEF_OAT_SUPPORT)
  #include "OAT/pyOAT.hpp"
#endif

#if defined(LIEF_VDEX_SUPPORT)
  #include "VDEX/pyVDEX.hpp"
#endif

#if defined(LIEF_DEX_SUPPORT)
  #include "DEX/pyDEX.hpp"
#endif

#if defined(LIEF_ART_SUPPORT)
  #include "ART/pyART.hpp"
#endif


#include "platforms/android/pyAndroid.hpp"
#include "platforms/pyPlatform.hpp"


PYBIND11_MODULE(lief, LIEF_module) {

  LIEF_module.attr("__version__")   = py::str(LIEF_VERSION);
  LIEF_module.attr("__tag__")       = py::str(LIEF_TAG);
  LIEF_module.attr("__commit__")    = py::str(LIEF_COMMIT);
  LIEF_module.attr("__is_tagged__") = py::bool_(LIEF_TAGGED);
  LIEF_module.doc() = "Python API for LIEF";

  LIEF::init_python_platforms(LIEF_module);

  init_LIEF_Object_class(LIEF_module);

  init_LIEF_errors(LIEF_module);

  init_LIEF_Logger(LIEF_module);

  // Init custom LIEF exceptions
  init_LIEF_exceptions(LIEF_module);

  // Init the LIEF module
  LIEF::init_python_module(LIEF_module);

  init_hash_functions(LIEF_module);


  // Init the ELF module
#if defined(LIEF_ELF_SUPPORT)
  LIEF::ELF::init_python_module(LIEF_module);
#endif

  // Init the PE module
#if defined(LIEF_PE_SUPPORT)
  LIEF::PE::init_python_module(LIEF_module);
#endif

  // Init the MachO  module
#if defined(LIEF_MACHO_SUPPORT)
  LIEF::MachO::init_python_module(LIEF_module);
#endif

// Init the OAT  module
#if defined(LIEF_OAT_SUPPORT)
  LIEF::OAT::init_python_module(LIEF_module);
#endif

// Init the VDEX module
#if defined(LIEF_VDEX_SUPPORT)
  LIEF::VDEX::init_python_module(LIEF_module);
#endif

// Init the DEX module
#if defined(LIEF_DEX_SUPPORT)
  LIEF::DEX::init_python_module(LIEF_module);
#endif

// Init the ART module
#if defined(LIEF_ART_SUPPORT)
  LIEF::ART::init_python_module(LIEF_module);
#endif

  LIEF::Android::init_python_module(LIEF_module);

  // Init util functions
  init_utils_functions(LIEF_module);


  init_json_functions(LIEF_module);
}
