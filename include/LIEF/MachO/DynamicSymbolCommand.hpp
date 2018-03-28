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
#ifndef LIEF_MACHO_DYNAMIC_SYMBOL_COMMAND_H_
#define LIEF_MACHO_DYNAMIC_SYMBOL_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {
class LIEF_API DynamicSymbolCommand : public LoadCommand {
  public:
  DynamicSymbolCommand(void);
  DynamicSymbolCommand(const dysymtab_command *cmd);

  DynamicSymbolCommand& operator=(const DynamicSymbolCommand& copy);
  DynamicSymbolCommand(const DynamicSymbolCommand& copy);

  virtual ~DynamicSymbolCommand(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const DynamicSymbolCommand& rhs) const;
  bool operator!=(const DynamicSymbolCommand& rhs) const;

  virtual std::ostream& print(std::ostream& os) const override;

  //! Index of the first symbol in the group of local symbols.
  uint32_t idx_local_symbol(void) const;

  //! Number of symbols in the group of local symbols.
  uint32_t nb_local_symbols(void) const;

  //! Index of the first symbol in the group of defined external symbols.
  uint32_t idx_external_define_symbol(void) const;

  //! Number of symbols in the group of defined external symbols.
  uint32_t nb_external_define_symbols(void) const;

  //! Index of the first symbol in the group of undefined external symbols.
  uint32_t idx_undefined_symbol(void) const;

  //! Number of symbols in the group of undefined external symbols.
  uint32_t nb_undefined_symbols(void) const;

  //! Byte offset from the start of the file to the table of contents data
  //!
  //! Table of content is used by legacy Mach-O loader and this field should be
  //! set to 0
  uint32_t toc_offset(void) const;

  //! Number of entries in the table of contents.
  //!
  //! Should be set to 0 on recent Mach-O
  uint32_t nb_toc(void) const;

  //! Byte offset from the start of the file to the module table data.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t module_table_offset(void) const;

  //! Number of entries in the module table.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t nb_module_table(void) const;

  //! Byte offset from the start of the file to the external reference table data.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t external_reference_symbol_offset(void) const;

  //! Number of entries in the external reference table
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t nb_external_reference_symbols(void) const;

  //! Byte offset from the start of the file to the indirect symbol table data.
  //!
  //! Indirect symbol table is used by the loader to speed-up symbol resolution during
  //! the *lazy binding* process
  //!
  //! References:
  //!   * dyld-519.2.1/src/ImageLoaderMachOCompressed.cpp
  //!   * dyld-519.2.1/src/ImageLoaderMachOClassic.cpp
  uint32_t indirect_symbol_offset(void) const;

  //! Number of entries in the indirect symbol table.
  //!
  //! @see indirect_symbol_offset
  uint32_t nb_indirect_symbols(void) const;


  //! Byte offset from the start of the file to the external relocation table data.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t external_relocation_offset(void) const;

  //! Number of entries in the external relocation table.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t nb_external_relocations(void) const;

  //! Byte offset from the start of the file to the local relocation table data.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t local_relocation_offset(void) const;

  //! Number of entries in the local relocation table.
  //!
  //! This field seems unused by recent Mach-O loader and should be set to 0
  uint32_t nb_local_relocations(void) const;


  void idx_local_symbol(uint32_t value);
  void nb_local_symbols(uint32_t value);

  void idx_external_define_symbol(uint32_t value);
  void nb_external_define_symbols(uint32_t value);

  void idx_undefined_symbol(uint32_t value);
  void nb_undefined_symbols(uint32_t value);

  void toc_offset(uint32_t value);
  void nb_toc(uint32_t value);

  void module_table_offset(uint32_t value);
  void nb_module_table(uint32_t value);

  void external_reference_symbol_offset(uint32_t value);
  void nb_external_reference_symbols(uint32_t value);

  void indirect_symbol_offset(uint32_t value);
  void nb_indirect_symbols(uint32_t value);

  void external_relocation_offset(uint32_t value);
  void nb_external_relocations(uint32_t value);

  void local_relocation_offset(uint32_t value);
  void nb_local_relocations(uint32_t value);

  private:
  uint32_t idx_local_symbol_;
  uint32_t nb_local_symbols_;

  uint32_t idx_external_define_symbol_;
  uint32_t nb_external_define_symbols_;

  uint32_t idx_undefined_symbol_;
  uint32_t nb_undefined_symbols_;

  uint32_t toc_offset_;
  uint32_t nb_toc_;

  uint32_t module_table_offset_;
  uint32_t nb_module_table_;

  uint32_t external_reference_symbol_offset_;
  uint32_t nb_external_reference_symbols_;

  uint32_t indirect_sym_offset_;
  uint32_t nb_indirect_symbols_;

  uint32_t external_relocation_offset_;
  uint32_t nb_external_relocations_;

  uint32_t local_relocation_offset_;
  uint32_t nb_local_relocations_;
};

}
}
#endif
