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
#include "LIEF/logging++.hpp"

namespace LIEF {
namespace MachO {

template<class T>
bool Binary::has_command(void) const {
  static_assert(std::is_base_of<LoadCommand, T>::value, "Require inheritance of 'LoadCommand'");
  auto&& it_cmd = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [] (const LoadCommand* command) {
        return typeid(T) == typeid(*command);
      });
  return it_cmd != std::end(this->commands_);
}

template<class T>
T& Binary::command(void) {
  static_assert(std::is_base_of<LoadCommand, T>::value, "Require inheritance of 'LoadCommand'");
  return const_cast<T&>(static_cast<const Binary*>(this)->command<T>());
}

template<class T>
const T& Binary::command(void) const {
  static_assert(std::is_base_of<LoadCommand, T>::value, "Require inheritance of 'LoadCommand'");
  if (not this->has_command<T>()) {
    throw not_found("Unable to find the " + std::string(typeid(T).name()));
  }

  if (this->count_commands<T>() > 1) {
    LOG(WARNING) << "Multiple " + std::string(typeid(T).name()) + " command. Return the first one!";
  }

  auto&& it_cmd = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [] (const LoadCommand* command) {
        return typeid(T) == typeid(*command);
      });

  return *dynamic_cast<T*>(*it_cmd);

}

template<class T>
size_t Binary::count_commands(void) const {
  static_assert(std::is_base_of<LoadCommand, T>::value, "Require inheritance of 'LoadCommand'");

  size_t nb_cmd = std::count_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [] (const LoadCommand* command) {
        return typeid(T) == typeid(*command);
      });
  return nb_cmd;

}


}
}
