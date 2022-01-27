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
#ifndef LIEF_PE_PARSER_H_
#define LIEF_PE_PARSER_H_

#include <set>
#include <string>
#include <vector>

#include "LIEF/visibility.h"
#include "LIEF/utils.hpp"

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/PE/enums.hpp"

struct Profiler;

namespace LIEF {
class BinaryStream;

namespace PE {
class Debug;
class ResourceNode;
class Binary;

namespace details {
struct pe_resource_directory_table;
}

//! Main interface to parse PE binaries. In particular the **static** functions:
//! Parser::parse should be used to get a LIEF::PE::Binary
class LIEF_API Parser : public LIEF::Parser {
  public:
  friend struct ::Profiler;

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
  static std::unique_ptr<Binary> parse(const std::string& filename);

  //! Parse a PE binary from a data buffer
  static std::unique_ptr<Binary> parse(const std::vector<uint8_t>& data, const std::string& name = "");

  Parser& operator=(const Parser& copy) = delete;
  Parser(const Parser& copy)            = delete;

  private:
  Parser(const std::string& file);
  Parser(const std::vector<uint8_t>& data, const std::string& name);

  ~Parser();
  Parser();

  void init(const std::string& name = "");

  template<typename PE_T>
  void parse();

  void parse_exports();
  void parse_sections();

  template<typename PE_T>
  bool parse_headers();

  void parse_configuration();

  template<typename PE_T>
  void parse_data_directories();

  template<typename PE_T>
  void parse_import_table();

  void parse_export_table();
  void parse_debug();
  void parse_debug_code_view(Debug& debug_info);
  void parse_debug_pogo(Debug& debug_info);

  template<typename PE_T>
  void parse_tls();

  template<typename PE_T>
  void parse_load_config();

  void parse_relocations();
  void parse_resources();
  void parse_string_table();
  void parse_symbols();
  void parse_signature();
  void parse_overlay();
  void parse_dos_stub();
  void parse_rich_header();

  ResourceNode* parse_resource_node(
      const details::pe_resource_directory_table& directory_table,
      uint32_t base_offset, uint32_t current_offset, uint32_t depth = 0);


  std::unique_ptr<BinaryStream> stream_;
  Binary*                       binary_{nullptr};
  PE_TYPE                       type_;
  std::set<uint32_t>            resource_visited_;
};


}
}
#endif
