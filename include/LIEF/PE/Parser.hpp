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

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/PE/Binary.hpp"

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"

#include "LIEF/PE/EnumToString.hpp"



namespace LIEF {
namespace PE {
class DLL_PUBLIC Parser : public LIEF::Parser {
  public:
    static Binary* parse(const std::string& filename);
    static Binary* parse(const std::vector<uint8_t>& data, const std::string& name = "");

    Parser& operator=(const Parser& copy) = delete;
    Parser(const Parser& copy)            = delete;

  private:
    Parser(const std::string& file);
    Parser(const std::vector<uint8_t>& data, const std::string& name);

    ~Parser(void);
    Parser(void);

    void init(const std::string& name = "");

    template<typename PE_T>
    void build(void);

    void build_exports(void);
    void build_sections(void);

    template<typename PE_T>
    void build_headers(void);

    void build_configuration(void);

    template<typename PE_T>
    void build_data_directories(void);

    template<typename PE_T>
    void build_import_table(void);

    void build_export_table(void);
    void build_debug(void);

    template<typename PE_T>
    void build_tls(void);

    void build_relocations(void);
    void build_resources(void);
    void build_string_table(void);
    void build_symbols(void);
    void build_signature(void);
    void build_overlay(void);
    void build_dos_stub(void);
    void build_rich_header(void);

    ResourceNode* build_resource_node(
        const pe_resource_directory_table *directory_table,
        uint32_t base_offset, uint32_t depth = 0);


    std::unique_ptr<VectorStream> stream_;
    Binary*                       binary_;
    PE_TYPE                       type_;
    std::set<uint32_t>            resource_visited_;
};


}
}
#endif
