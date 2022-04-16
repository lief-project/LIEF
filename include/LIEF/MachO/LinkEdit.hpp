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
#ifndef LIEF_MACHO_LINK_EDIT_H_
#define LIEF_MACHO_LINK_EDIT_H_

#include <string>
#include <vector>
#include <iostream>
#include <memory>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/SegmentCommand.hpp"


namespace LIEF {
namespace MachO {

class Binary;
class BinaryParser;
class Builder;
class CodeSignatureDir;
class DataInCode;
class DyldChainedFixups;
class DyldExportsTrie;
class DyldInfo;
class FunctionStarts;
class LinkerOptHint;
class SymbolCommand;
class TwoLevelHints;

class LIEF_API LinkEdit : public SegmentCommand {

  friend class BinaryParser;
  friend class Binary;
  friend class Builder;

  public:
  using SegmentCommand::SegmentCommand;

  LinkEdit& operator=(LinkEdit other);
  LinkEdit(const LinkEdit& copy);

  void swap(LinkEdit& other);

  SegmentCommand* clone() const override;

  ~LinkEdit() override;

  bool operator==(const SegmentCommand& rhs) const;
  bool operator!=(const SegmentCommand& rhs) const;

  static bool classof(const LoadCommand* cmd);
  static bool segmentof(const SegmentCommand& segment);

  private:

  LIEF_LOCAL void update_data(update_fnc_t f) override;
  LIEF_LOCAL void update_data(update_fnc_ws_t f, size_t where, size_t size) override;

  //x-ref to keep the spans in a consistent state
  DyldInfo* dyld_                    = nullptr;
  DyldChainedFixups* chained_fixups_ = nullptr;
  DyldExportsTrie* exports_trie_     = nullptr;
  SegmentSplitInfo* seg_split_       = nullptr;
  FunctionStarts* fstarts_           = nullptr;
  DataInCode* data_code_             = nullptr;
  CodeSignatureDir* code_sig_dir_    = nullptr;
  LinkerOptHint* linker_opt_         = nullptr;
  SymbolCommand* symtab_             = nullptr;
  TwoLevelHints* two_lvl_hint_       = nullptr;
  CodeSignature* code_sig_           = nullptr;
};

}
}
#endif
