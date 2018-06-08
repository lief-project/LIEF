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
#ifndef LIEF_OAT_PARSER_H_
#define LIEF_OAT_PARSER_H_


#include <memory>

#include "LIEF/visibility.h"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include "LIEF/ELF.hpp"

#include "LIEF/OAT/Binary.hpp"


namespace LIEF {
namespace VDEX {
class File;
}
namespace OAT {

//! @brief Class which parse an OAT file and transform into a OAT::Binary
class LIEF_API Parser : public LIEF::Parser {
  public:
    //! Parse an OAT file
    static std::unique_ptr<Binary> parse(const std::string& oat_file);
    static std::unique_ptr<Binary> parse(const std::string& oat_file, const std::string& vdex_file);

    static std::unique_ptr<Binary> parse(const std::vector<uint8_t>& data, const std::string& name = "");

    Parser& operator=(const Parser& copy) = delete;
    Parser(const Parser& copy)            = delete;

  private:
    Parser(void);
    Parser(const std::string& oat_file);
    Parser(const std::vector<uint8_t>& data, const std::string& name);
    ~Parser(void);

    bool has_vdex(void) const;
    void set_vdex(VDEX::File* file);

    void bind_vdex(void);

    template<typename OAT_T>
    void parse_binary();

    template<typename OAT_T>
    void parse_header(void);

    template<typename OAT_T>
    void parse_header_keys(void);

    template<typename OAT_T>
    void parse_dex_files(void);

    template<typename OAT_T>
    void parse_type_lookup_table(void);

    template<typename OAT_T>
    void parse_oat_classes(void);

    template<typename OAT_T>
    void parse_oat_methods(uint64_t methods_offsets, Class* clazz, const DEX::Class& dex_class);

    void init(const std::string& name = "");

    LIEF::OAT::Binary* oat_binary_{nullptr};
    LIEF::VDEX::File* vdex_file_{nullptr};

    std::unique_ptr<VectorStream> stream_;
    uint64_t data_address_;
    uint64_t data_size_;

    uint64_t exec_start_;
    uint64_t exec_size_;
};




} // namespace OAT
} // namespace LIEF
#endif
