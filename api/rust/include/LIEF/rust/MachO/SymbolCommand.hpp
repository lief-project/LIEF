/* Copyright 2024 R. Thomas
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

#pragma once
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_SymbolCommand : public MachO_Command {
  using lief_t = LIEF::MachO::SymbolCommand;
  public:
  MachO_SymbolCommand(const lief_t& base) : MachO_Command(base) {}
  uint32_t symbol_offset() const { return impl().symbol_offset(); };
  uint32_t numberof_symbols() const { return impl().numberof_symbols(); };
  uint32_t strings_offset() const { return impl().strings_offset(); };
  uint32_t strings_size() const { return impl().strings_size(); };
  uint32_t original_str_size() const { return impl().original_str_size(); };
  uint32_t original_nb_symbols() const { return impl().original_nb_symbols(); };

  auto symbol_table() const { return make_span(impl().symbol_table()); }
  auto string_table() const { return make_span(impl().string_table()); }

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
