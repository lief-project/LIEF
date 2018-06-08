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
#ifndef LIEF_PE_PARSER_H_
#define LIEF_PE_PARSER_H_

#include <string>
#include <vector>

#include "LIEF/exception.hpp"
#include "LIEF/visibility.h"
#include "LIEF/utils.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/Binary.hpp"

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include "LIEF/PE/EnumToString.hpp"



namespace LIEF {
namespace PE {
class LIEF_API Parser : public LIEF::Parser {

  //! @brief Minimum size for a DLL's name
  static constexpr unsigned MIN_DLL_NAME_SIZE = 4;

  //! @brief Maximum size of the data read
  static constexpr size_t MAX_DATA_SIZE = 3_GB;

  static constexpr size_t MAX_TLS_CALLBACKS = 3000;


  public:
    static std::unique_ptr<Binary> parse(const std::string& filename);
    static std::unique_ptr<Binary> parse(const std::vector<uint8_t>& data, const std::string& name = "");

    Parser& operator=(const Parser& copy) = delete;
    Parser(const Parser& copy)            = delete;

  private:
    Parser(const std::string& file);
    Parser(const std::vector<uint8_t>& data, const std::string& name);

    ~Parser(void);
    Parser(void);

    void init(const std::string& name = "");

    template<typename PE_T>
    void parse(void);

    void parse_exports(void);
    void parse_sections(void);

    template<typename PE_T>
    bool parse_headers(void);

    void parse_configuration(void);

    template<typename PE_T>
    void parse_data_directories(void);

    template<typename PE_T>
    void parse_import_table(void);

    void parse_export_table(void);
    void parse_debug(void);
    void parse_debug_code_view(void);

    template<typename PE_T>
    void parse_tls(void);

    template<typename PE_T>
    void parse_load_config(void);

    void parse_relocations(void);
    void parse_resources(void);
    void parse_string_table(void);
    void parse_symbols(void);
    void parse_signature(void);
    void parse_overlay(void);
    void parse_dos_stub(void);
    void parse_rich_header(void);

    ResourceNode* parse_resource_node(
        const pe_resource_directory_table *directory_table,
        uint32_t base_offset, uint32_t current_offset, uint32_t depth = 0);


    std::unique_ptr<VectorStream> stream_;
    Binary*                       binary_;
    PE_TYPE                       type_;
    std::set<uint32_t>            resource_visited_;
};


}
}
#endif
