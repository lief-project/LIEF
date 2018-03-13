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
#ifndef LIEF_ELF_BUIDLER_H_
#define LIEF_ELF_BUIDLER_H_

#include <vector>
#include <memory>
#include <algorithm>
#include <string>

#include "LIEF/visibility.h"
#include "LIEF/iostream.hpp"

#include "LIEF/ELF/Binary.hpp"

namespace LIEF {
namespace ELF {

//! @brief Class which take a ELF::Binary object and reconstruct a valid binary
class LIEF_API Builder {
  public:
    Builder(Binary *binary);

    Builder(void) = delete;
    ~Builder(void);

    void build(void);

    Builder& empties_gnuhash(bool flag = true);

    const std::vector<uint8_t>& get_build(void);
    void write(const std::string& filename) const;

  protected:
    template<typename ELF_T>
    void build(void);

    template<typename ELF_T>
    void build(const Header& header);

    template<typename ELF_T>
    void build_sections(void);

    template<typename ELF_T>
    void build_segments(void);

    template<typename ELF_T>
    void build_static_symbols(void);

    template<typename ELF_T>
    void build_dynamic(void);

    template<typename ELF_T>
    void build_dynamic_section(void);

    template<typename ELF_T>
    void build_dynamic_symbols(void);

    template<typename ELF_T>
    void build_dynamic_relocations(void);

    template<typename ELF_T>
    void build_pltgot_relocations(void);

    template<typename ELF_T>
    void build_hash_table(void);

    template<typename ELF_T>
    void build_symbol_hash(void);

    template<typename ELF_T>
    void build_symbol_gnuhash(void);

    void build_empty_symbol_gnuhash(void);

    template<typename ELF_T>
    void build_symbol_requirement(void);

    template<typename ELF_T>
    void build_symbol_definition(void);

    template<typename T, typename HANDLER>
    std::vector<std::string> optimize(const HANDLER& e);

    template<typename ELF_T>
    void build_symbol_version(void);

    template<typename ELF_T>
    void build_interpreter(void);

    template<typename ELF_T>
    void build_notes(void);

    void build(NOTE_TYPES type);

    size_t note_offset(const Note& note);

    bool empties_gnuhash_;

    template<typename ELF_T>
    void relocate_dynamic_array(DynamicEntryArray& entry_array, DynamicEntry& entry_size);

    mutable vector_iostream ios_;
    Binary*           binary_;


};

} // namespace ELF
} // namespace LIEF




#endif
