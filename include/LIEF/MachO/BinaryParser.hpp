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
#include "LIEF/errors.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/MachO/enums.hpp"
#include "LIEF/MachO/ParserConfig.hpp"
#include "LIEF/MachO/type_traits.hpp"

namespace LIEF {
class BinaryStream;

namespace MachO {
class Section;
class Parser;
struct ParserConfig;
class DylibCommand;
class Symbol;

//! Class used to parse a **single** binary (i.e. non-FAT)
//!
//! @warning This class should not be directly used.
//!
//! @see MachO::Parser
class LIEF_API BinaryParser : public LIEF::Parser {

  friend class MachO::Parser;

  //! Maximum number of relocations
  constexpr static size_t MAX_RELOCATIONS = std::numeric_limits<uint16_t>::max();

  //! Maximum number of MachO LoadCommand
  constexpr static size_t MAX_COMMANDS = std::numeric_limits<uint16_t>::max();

  public:
  static std::unique_ptr<Binary> parse(const std::string& file);
  static std::unique_ptr<Binary> parse(const std::string& file, const ParserConfig& conf);
  static std::unique_ptr<Binary> parse(const std::vector<uint8_t>& data,
                                       const ParserConfig& conf = ParserConfig::deep());

  static std::unique_ptr<Binary> parse(const std::vector<uint8_t>& data, uint64_t fat_offset,
                                       const ParserConfig& conf = ParserConfig::deep());

  static std::unique_ptr<Binary> parse(std::unique_ptr<BinaryStream> stream, uint64_t fat_offset,
                                       const ParserConfig& conf);

  BinaryParser& operator=(const BinaryParser& copy) = delete;
  BinaryParser(const BinaryParser& copy) = delete;

  ~BinaryParser();

  private:
  BinaryParser();

  ok_error_t init_and_parse();

  template<class MACHO_T>
  ok_error_t parse();

  template<class MACHO_T>
  ok_error_t parse_header();

  template<class MACHO_T>
  ok_error_t parse_load_commands();

  template<class MACHO_T>
  ok_error_t parse_relocations(Section& section);

  // Dyld info parser
  // ================

  // Rebase
  // ------
  template<class MACHO_T>
  ok_error_t parse_dyldinfo_rebases();

  // Bindings
  // --------
  template<class MACHO_T>
  ok_error_t parse_dyldinfo_binds();

  template<class MACHO_T>
  ok_error_t parse_dyldinfo_generic_bind();

  template<class MACHO_T>
  ok_error_t parse_dyldinfo_weak_bind();

  template<class MACHO_T>
  ok_error_t parse_dyldinfo_lazy_bind();

  using it_opaque_segments = void*; // To avoid including Binary.hpp. It must contains it_opaque_segments

  template<class MACHO_T>
  ok_error_t do_bind(BINDING_CLASS cls, uint8_t type, uint8_t segment_idx,
                     uint64_t segment_offset, const std::string& symbol_name,
                     int32_t ord, int64_t addend, bool is_weak,
                     bool is_non_weak_definition, it_opaque_segments segments_ptr, uint64_t offset = 0);


  template<class MACHO_T>
  ok_error_t do_rebase(uint8_t type, uint8_t segment_idx, uint64_t segment_offset,
                       const it_opaque_segments segments);

  // Exports
  // -------
  ok_error_t parse_dyldinfo_export();

  ok_error_t parse_export_trie(uint64_t start, uint64_t end, const std::string& prefix);

  std::unique_ptr<BinaryStream>  stream_;
  std::unique_ptr<Binary>        binary_;
  MACHO_TYPES                    type_ = MACHO_TYPES::MH_MAGIC_64;
  bool                           is64_ = true;
  ParserConfig                   config_;
  std::set<uint64_t>             visited_;
  std::map<std::string, Symbol*> memoized_symbols_;
  std::map<uint64_t, Symbol*>    memoized_symbols_by_address_;

  std::vector<DylibCommand*> binding_libs_;
  std::set<uint64_t> dyld_reloc_addrs_;
};


} // namespace MachO
} // namespace LIEF
#endif
