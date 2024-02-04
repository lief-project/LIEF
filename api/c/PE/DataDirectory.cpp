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
#include "DataDirectory.hpp"

namespace LIEF {
namespace PE {
void init_c_data_directories(Pe_Binary_t* c_binary, Binary* binary) {

  Binary::it_data_directories data_directories = binary->data_directories();

  c_binary->data_directories = static_cast<Pe_DataDirectory_t**>(
      malloc((data_directories.size() + 1) * sizeof(Pe_DataDirectory_t**)));

  for (size_t i = 0; i < data_directories.size(); ++i) {

    c_binary->data_directories[i] = static_cast<Pe_DataDirectory_t*>(malloc(sizeof(Pe_DataDirectory_t)));
    c_binary->data_directories[i]->rva  = data_directories[i].RVA();
    c_binary->data_directories[i]->size = data_directories[i].size();
  }
  c_binary->data_directories[data_directories.size()] = nullptr;



}



void destroy_data_directories(Pe_Binary_t* c_binary) {

  Pe_DataDirectory_t **data_directories = c_binary->data_directories;
  for (size_t idx = 0; data_directories[idx] != nullptr; ++idx) {
    free(data_directories[idx]);
  }
  free(c_binary->data_directories);

}

}
}


