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
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/rust/MachO/LoadCommand.hpp"

class MachO_DynamicSymbolCommand : public MachO_Command {
  public:
  using lief_t = LIEF::MachO::DynamicSymbolCommand;
  MachO_DynamicSymbolCommand(const lief_t& base) : MachO_Command(base) {}

  uint32_t idx_local_symbol() const { return impl().idx_local_symbol(); };
  uint32_t nb_local_symbols() const { return impl().nb_local_symbols(); };
  uint32_t idx_external_define_symbol() const { return impl().idx_external_define_symbol(); };
  uint32_t nb_external_define_symbols() const { return impl().nb_external_define_symbols(); };
  uint32_t idx_undefined_symbol() const { return impl().idx_undefined_symbol(); };
  uint32_t nb_undefined_symbols() const { return impl().nb_undefined_symbols(); };
  uint32_t toc_offset() const { return impl().toc_offset(); };
  uint32_t nb_toc() const { return impl().nb_toc(); };
  uint32_t module_table_offset() const { return impl().module_table_offset(); };
  uint32_t nb_module_table() const { return impl().nb_module_table(); };
  uint32_t external_reference_symbol_offset() const { return impl().external_reference_symbol_offset(); };
  uint32_t nb_external_reference_symbols() const { return impl().nb_external_reference_symbols(); };
  uint32_t indirect_symbol_offset() const { return impl().indirect_symbol_offset(); };
  uint32_t nb_indirect_symbols() const { return impl().nb_indirect_symbols(); };
  uint32_t external_relocation_offset() const { return impl().external_relocation_offset(); };
  uint32_t nb_external_relocations() const { return impl().nb_external_relocations(); };
  uint32_t local_relocation_offset() const { return impl().local_relocation_offset(); };
  uint32_t nb_local_relocations() const { return impl().nb_local_relocations(); };

  static bool classof(const MachO_Command& cmd) {
    return lief_t::classof(&cmd.get());
  }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
