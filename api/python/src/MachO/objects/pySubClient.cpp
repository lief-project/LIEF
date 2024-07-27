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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/MachO/SubClient.hpp"

#include "MachO/pyMachO.hpp"

namespace LIEF::MachO::py {

template<>
void create<SubClient>(nb::module_& m) {

  nb::class_<SubClient, LoadCommand>(m, "SubClient",
      R"delim(
      Class that represents the SubClient command.
      Accodring to the Mach-O ``loader.h`` documentation:

      > For dynamically linked shared libraries that are subframework of an umbrella
      > framework they can allow clients other than the umbrella framework or other
      > subframeworks in the same umbrella framework.  To do this the subframework
      > is built with "-allowable_client client_name" and an LC_SUB_CLIENT load
      > command is created for each -allowable_client flag.  The client_name is
      > usually a framework name.  It can also be a name used for bundles clients
      > where the bundle is built with "-client_name client_name".
      )delim"_doc)

    .def_prop_rw("client",
        nb::overload_cast<>(&SubClient::client, nb::const_),
        nb::overload_cast<std::string>(&SubClient::client),
        "Name of the sub client"_doc)

    LIEF_DEFAULT_STR(SubClient);
}
}
