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
#ifndef LIEF_PE_PARSER_H
#define LIEF_PE_PARSER_H

#include <set>
#include <string>
#include <vector>

#include "LIEF/visibility.h"
#include "LIEF/utils.hpp"
#include "LIEF/errors.hpp"

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/ParserConfig.hpp"

namespace LIEF {
class BinaryStream;

namespace PE {
class Debug;
class ResourceNode;
class Binary;
class DelayImport;

namespace details {
struct pe_resource_directory_table;
struct pe_debug;
}

//! Main interface to parse PE binaries. In particular the **static** functions:
//! Parser::parse should be used to get a LIEF::PE::Binary
class LIEF_API Parser : public LIEF::Parser {
  public:

  //! Maximum size of the data read
  static constexpr size_t MAX_DATA_SIZE = 3_GB;

  static constexpr size_t MAX_TLS_CALLBACKS = 3000;

  // According to https://stackoverflow.com/a/265782/87207
  static constexpr size_t MAX_DLL_NAME_SIZE = 255;

  //! Max size of the padding section
  static constexpr size_t MAX_PADDING_SIZE = 1_GB;

  public:
  //! Check if the given name is a valid import.
  //!
  //! This check verified that:
  //!   1. The name is not too large or empty (cf. https://stackoverflow.com/a/23340781)
  //!   2. All the characters are printable
  static bool is_valid_import_name(const std::string& name);

  //! Check if the given name is a valid DLL name.
  //!
  //! This check verifies that:
  //!   1. The name of the DLL is at 4
  //!   2. All the characters are printable
  static bool is_valid_dll_name(const std::string& name);

  public:
  //! Parse a PE binary from the given filename
  static std::unique_ptr<Binary> parse(const std::string& filename,
                                       const ParserConfig& conf = ParserConfig::all());

  //! Parse a PE binary from a data buffer
  static std::unique_ptr<Binary> parse(std::vector<uint8_t> data,
                                       const ParserConfig& conf = ParserConfig::all());

  //! Parse a PE binary from the given BinaryStream
  static std::unique_ptr<Binary> parse(std::unique_ptr<BinaryStream> stream,
                                       const ParserConfig& conf = ParserConfig::all());

  Parser& operator=(const Parser& copy) = delete;
  Parser(const Parser& copy)            = delete;

  private:
  Parser(const std::string& file);
  Parser(std::vector<uint8_t> data);
  Parser(std::unique_ptr<BinaryStream> stream);

  ~Parser() override;
  Parser();

  void init(const ParserConfig& config);

  template<typename PE_T>
  ok_error_t parse();

  ok_error_t parse_exports();
  ok_error_t parse_sections();

  template<typename PE_T>
  ok_error_t parse_headers();

  ok_error_t parse_configuration();

  template<typename PE_T>
  ok_error_t parse_data_directories();

  template<typename PE_T>
  ok_error_t parse_import_table();

  template<typename PE_T>
  ok_error_t parse_delay_imports();

  template<typename PE_T>
  ok_error_t parse_delay_names_table(DelayImport& import, uint32_t names_offset);

  ok_error_t parse_export_table();
  ok_error_t parse_debug();

  std::unique_ptr<Debug> parse_code_view(const details::pe_debug& debug_info);
  std::unique_ptr<Debug> parse_pogo(const details::pe_debug& debug_info);
  std::unique_ptr<Debug> parse_repro(const details::pe_debug& debug_info);

  template<typename PE_T>
  ok_error_t parse_tls();

  template<typename PE_T>
  ok_error_t parse_load_config();

  ok_error_t parse_relocations();
  ok_error_t parse_resources();
  ok_error_t parse_string_table();
  ok_error_t parse_symbols();
  ok_error_t parse_signature();
  ok_error_t parse_overlay();
  ok_error_t parse_dos_stub();
  ok_error_t parse_rich_header();

  std::unique_ptr<ResourceNode> parse_resource_node(
      const details::pe_resource_directory_table& directory_table,
      uint32_t base_offset, uint32_t current_offset, uint32_t depth = 0);


  PE_TYPE type_ = PE_TYPE::PE32_PLUS;
  std::unique_ptr<Binary> binary_;
  std::set<uint32_t> resource_visited_;
  std::unique_ptr<BinaryStream> stream_;
  ParserConfig config_;
};


}
}
#endif
