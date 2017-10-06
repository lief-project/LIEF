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
#include "pyPE.hpp"
void init_PE_load_configurations(py::module& m) {
  init_PE_LoadConfiguration_class(m);
  init_PE_LoadConfigurationV0_class(m);
  init_PE_LoadConfigurationV1_class(m);
  init_PE_LoadConfigurationV2_class(m);
  init_PE_LoadConfigurationV3_class(m);
  init_PE_LoadConfigurationV4_class(m);
  init_PE_LoadConfigurationV5_class(m);
  init_PE_LoadConfigurationV6_class(m);
  init_PE_LoadConfigurationV7_class(m);
}
