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
#ifndef LIEF_DEX_PARSER_H_
#define LIEF_DEX_PARSER_H_

#include <memory>

#include "LIEF/visibility.h"

#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/DEX/File.hpp"


namespace LIEF {
namespace DEX {
class Class;
class Method;

//! @brief Class which parse a DEX file and transform into a DEX::File object
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
    ~Parser(void);

    void init(const std::string& name, dex_version_t version);

    template<typename DEX_T>
    void parse_file(void);

    template<typename DEX_T>
    void parse_header(void);

    template<typename DEX_T>
    void parse_map(void);

    template<typename DEX_T>
    void parse_strings(void);

    template<typename DEX_T>
    void parse_types(void);

    template<typename DEX_T>
    void parse_fields(void);

    template<typename DEX_T>
    void parse_prototypes(void);

    template<typename DEX_T>
    void parse_methods(void);

    template<typename DEX_T>
    void parse_classes(void);

    template<typename DEX_T>
    void parse_class_data(uint32_t offset, Class* cls);

    template<typename DEX_T>
    void parse_method(size_t index, Class* cls, bool is_virtual);

    template<typename DEX_T>
    void parse_code_info(uint32_t offset, Method* method);

    void resolve_inheritance(void);

    void resolve_external_methods(void);

    void resolve_types(void);

    LIEF::DEX::File* file_;

    // Map of inheritance relationship when parsing classes ('parse_classes')
    // The key is the parent class name of the value
    std::unordered_multimap<std::string, Class*> inheritance_;

    // Map of method/class relationship when parsing methods ('parse_methods')
    // The key is the Class name in which the method is defined
    std::unordered_multimap<std::string, Method*> class_method_map_;

    std::unordered_multimap<std::string, Type*> class_type_map_;

    std::unique_ptr<VectorStream> stream_;
};




} // namespace DEX
} // namespace LIEF
#endif
