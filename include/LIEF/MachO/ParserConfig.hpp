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
#ifndef LIEF_MACHO_PARSER_CONFIG_H_
#define LIEF_MACHO_PARSER_CONFIG_H_
#include "LIEF/visibility.h"

namespace LIEF {
namespace MachO {

//! This structure is used to tweak the MachO Parser (MachO::Parser)
struct LIEF_API ParserConfig {
  //! Return a parser configuration such as all the objects supported by
  //! LIEF are parsed
  static ParserConfig deep();

  //! Return a configuration to parse the most important MachO
  //! structures
  static ParserConfig quick();

  //! If ``flag`` is set to ``true``, Exports, Bindings and Rebases opcodes are
  //! parsed.
  //!
  //! @warning Enabling this flag can slow down the parsing
  ParserConfig& full_dyldinfo(bool flag);

  bool parse_dyld_exports = true;   ///< Parse the Dyld export trie
  bool parse_dyld_bindings = true;  ///< Parse the Dyld binding opcodes
  bool parse_dyld_rebases = true;   ///< Parse the Dyld rebase opcodes
};

}  // namespace MachO
}  // namespace LIEF
#endif
