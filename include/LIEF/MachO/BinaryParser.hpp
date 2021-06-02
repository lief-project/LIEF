/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#ifndef LIEF_MACHO_BINARY_PARSER_H_
#define LIEF_MACHO_BINARY_PARSER_H_
#include <memory>
#include <string>
#include <vector>
#include <limits>
#include <set>
#include <map>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/MachO/enums.hpp"
#include "LIEF/MachO/ParserConfig.hpp"
#include "LIEF/MachO/type_traits.hpp"

namespace LIEF {
class BinaryStream;

namespace MachO {
class Section;
class Parser;
class ParserConfig;

//! @brief Class used to parse **single** binary (i.e. **not** FAT)
//! @see MachO::Parser
class LIEF_API BinaryParser : public LIEF::Parser {

  friend class MachO::Parser;

  //! @brief Maximum number of relocations
  constexpr static size_t MAX_RELOCATIONS = std::numeric_limits<uint16_t>::max();
  constexpr static size_t MAX_COMMANDS    = std::numeric_limits<uint8_t>::max();

  public:
  BinaryParser(const std::string& file, const ParserConfig& conf = ParserConfig::deep());
  BinaryParser(const std::vector<uint8_t>& data, uint64_t fat_offset = 0, const ParserConfig& conf = ParserConfig::deep());
  BinaryParser(void);

  BinaryParser& operator=(const BinaryParser& copy) = delete;
  BinaryParser(const BinaryParser& copy) = delete;

  ~BinaryParser(void);

  Binary* get_binary(void);

  private:
  BinaryParser(std::unique_ptr<BinaryStream>&& stream, uint64_t fat_offset = 0, const ParserConfig& conf = ParserConfig::deep());

  void init(void);

  template<class MACHO_T>
  void parse(void);

  template<class MACHO_T>
  void parse_header(void);

  template<class MACHO_T>
  void parse_load_commands(void);

  template<class MACHO_T>
  void parse_relocations(Section& section);

  // Dyld info parser
  // ================

  // Rebase
  // ------
  template<class MACHO_T>
  void parse_dyldinfo_rebases(void);

  // Bindings
  // --------
  template<class MACHO_T>
  void parse_dyldinfo_binds(void);

  template<class MACHO_T>
  void parse_dyldinfo_generic_bind(void);

  template<class MACHO_T>
  void parse_dyldinfo_weak_bind(void);

  template<class MACHO_T>
  void parse_dyldinfo_lazy_bind(void);

  template<class MACHO_T>
  void do_bind(BINDING_CLASS cls,
      uint8_t type,
      uint8_t segment_idx,
      uint64_t segment_offset,
      const std::string& symbol_name,
      int32_t ord,
      int64_t addend,
      bool is_weak,
      bool is_non_weak_definition,
      it_segments& segments,
      uint64_t offset = 0
  );


  template<class MACHO_T>
  void do_rebase(uint8_t type, uint8_t segment_idx, uint64_t segment_address, const it_segments& segments);

  // Exports
  // -------
  void parse_dyldinfo_export(void);

  void parse_export_trie(uint64_t start, uint64_t end, const std::string& prefix);

  std::unique_ptr<BinaryStream>  stream_;
  Binary*                        binary_{nullptr};
  MACHO_TYPES                    type_;
  bool                           is64_;
  ParserConfig                   config_;
  std::set<uint64_t>             visited_;
  std::map<std::string, Symbol*> memoized_symbols_;
  std::map<uint64_t, Symbol*>    memoized_symbols_by_address_;
};


} // namespace MachO
} // namespace LIEF
#endif
