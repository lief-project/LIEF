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
#include "LoadCommand.hpp"

namespace LIEF {
namespace MachO {
void init_c_commands(Macho_Binary_t* c_binary, Binary* binary) {
  Binary::it_commands commands = binary->commands();

  c_binary->commands = static_cast<Macho_Command_t**>(
      malloc((commands.size() + 1) * sizeof(Macho_Command_t**)));

  for (size_t i = 0; i < commands.size(); ++i) {
    LoadCommand& cmd = commands[i];

    c_binary->commands[i] = static_cast<Macho_Command_t*>(malloc(sizeof(Macho_Command_t)));
    const std::vector<uint8_t>& cmd_content = cmd.data();
    auto* content = static_cast<uint8_t*>(malloc(cmd_content.size() * sizeof(uint8_t)));
    std::copy(
        std::begin(cmd_content),
        std::end(cmd_content),
        content);

    c_binary->commands[i]->command = static_cast<enum LIEF_MACHO_LOAD_COMMAND_TYPES>(cmd.command());
    c_binary->commands[i]->size    = cmd.size();
    c_binary->commands[i]->data    = content;
    c_binary->commands[i]->offset  = cmd.command_offset();
  }

  c_binary->commands[commands.size()] = nullptr;

}



void destroy_commands(Macho_Binary_t* c_binary) {
  Macho_Command_t **commands = c_binary->commands;
  for (size_t idx = 0; commands[idx] != nullptr; ++idx) {
    free(commands[idx]->data);
    free(commands[idx]);
  }
  free(c_binary->commands);

}

}
}


