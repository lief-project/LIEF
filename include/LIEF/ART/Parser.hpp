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
#ifndef LIEF_ART_PARSER_H_
#define LIEF_ART_PARSER_H_


#include <memory>

#include "LIEF/visibility.h"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ART/File.hpp"


namespace LIEF {
namespace ART {

//! @brief Class which parse an ART file and transform into a ART::File object
class LIEF_API Parser {
  public:
    static std::unique_ptr<File> parse(const std::string& file);
    static std::unique_ptr<File> parse(const std::vector<uint8_t>& data, const std::string& name = "");

    Parser& operator=(const Parser& copy) = delete;
    Parser(const Parser& copy)            = delete;

  private:
    Parser(void);
    Parser(const std::string& file);
    Parser(const std::vector<uint8_t>& data, const std::string& name);
    virtual ~Parser(void);

    void init(const std::string& name, art_version_t version);

    template<typename ART_T>
    void parse_file(void);

    template<typename ART_T>
    size_t parse_header(void);

    template<typename ART_T, typename PTR_T>
    void parse_sections(void);

    template<typename ART_T, typename PTR_T>
    void parse_roots(void);

    template<typename ART_T, typename PTR_T>
    void parse_methods(void);

    // Section parsing
    template<typename ART_T, typename PTR_T>
    void parse_objects(size_t offset, size_t size);

    template<typename ART_T, typename PTR_T>
    void parse_art_fields(size_t offset, size_t size);

    template<typename ART_T, typename PTR_T>
    void parse_art_methods(size_t offset, size_t size);

    template<typename ART_T, typename PTR_T>
    void parse_interned_strings(size_t offset, size_t size);

    // Parse an **Array** of java.lang.DexCache objects
    template<typename ART_T, typename PTR_T>
    void parse_dex_caches(size_t offset, size_t size);

    // Parse a **Single** java.lang.DexCache object
    template<typename ART_T, typename PTR_T>
    void parse_dex_cache(size_t object_offset);

    // Parse an **Array** of java.lang.Class objects
    template<typename ART_T, typename PTR_T>
    void parse_class_roots(size_t offset, size_t size);

    // Parse java.lang.Class objects
    template<typename ART_T, typename PTR_T>
    void parse_class(size_t offset);

    // Parse java.lang.String objects
    template<typename ART_T, typename PTR_T>
    void parse_jstring(size_t offset);


    //// Parse a **Single** java.lang.DexCache object
    //template<typename ART_T, typename PTR_T>
    //void parse_class_roots(size_t object_offset);


    LIEF::ART::File* file_;
    std::unique_ptr<VectorStream> stream_;
    uint32_t imagebase_;
};




} // namespace ART
} // namespace LIEF
#endif
