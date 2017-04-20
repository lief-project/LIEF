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
#ifndef LIEF_PE_BUILDER_H_
#define LIEF_PE_BUILDER_H_

#include <cstring>
#include <string>
#include <vector>
#include <iterator>
#include <iostream>
#include <ostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "LIEF/visibility.h"
#include "LIEF/utils.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/PE/Binary.hpp"


namespace LIEF {
namespace PE {

//! @brief Class which reconstruct a PE binary from a PE::Binary object
class DLL_PUBLIC Builder
{
  public:
    Builder(void) = delete;
    Builder(Binary* pe_binary);
    ~Builder(void);

    void build(void);

    template<typename PE_T>
    static std::vector<uint8_t> build_jmp(uint64_t address);

    template<typename PE_T>
    static std::vector<uint8_t> build_jmp_hook(uint64_t address);

    Builder& build_imports(bool flag = true);
    Builder& patch_imports(bool flag = true);
    Builder& build_relocations(bool flag = true);
    Builder& build_tls(bool flag = true);
    Builder& build_resources(bool flag);
    Builder& build_overlay(bool flag);

    const std::vector<uint8_t>& get_build(void);
    void write(const std::string& filename) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const Builder& b);

    Builder& operator<<(const DosHeader& dos_header);
    Builder& operator<<(const Header& bHeader);
    Builder& operator<<(const OptionalHeader& optional_header);
    Builder& operator<<(const DataDirectory& data_directory);
    Builder& operator<<(const Section& section);

  protected:
    template<typename PE_T>
    void build_optional_header(const OptionalHeader& optional_header);


    //! @brief Rebuild Import Table
    // TODO: Bug with x86
    template<typename PE_T>
    void build_import_table(void);

    template<typename PE_T>
    void build_tls(void);

    void build_symbols(void);
    void build_string_table(void);
    void build_relocation(void);
    void build_resources(void);
    void build_overlay(void);

    void compute_resources_size(
        ResourceNode *node,
        uint32_t *headerSize,
        uint32_t *dataSize,
        uint32_t *nameSize);

    void construct_resources(
        ResourceNode *node,
        std::vector<uint8_t> *content,
        uint32_t *offsetToHeader,
        uint32_t *offsetToData,
        uint32_t *offsetToName,
        uint32_t baseRVA,
        uint32_t depth);


    mutable vector_iostream ios_;
    Binary                 *binary_;

    bool build_imports_;
    bool patch_imports_;
    bool build_relocations_;
    bool build_tls_;
    bool build_resources_;
    bool build_overlay_;

};

}
}
#endif
