/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021, NVIDIA CORPORATION. All rights reserved
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
#include <string>
#include <set>
#include <unordered_map>
#include <functional>

#include "LIEF/errors.hpp"

#include "LIEF/visibility.h"
#include "LIEF/iostream.hpp"
#include "LIEF/ELF/enums.hpp"

#include "LIEF/ELF/enums.hpp"

struct Profiler;

namespace LIEF {
namespace ELF {
class Binary;
class Layout;
class Header;
class Note;
class DynamicEntryArray;
class DynamicEntry;
class Section;
class ExeLayout;
class ObjectFileLayout;
class Layout;
class Relocation;

//! Class which takes an ELF::Binary object and reconstructs a valid binary
class LIEF_API Builder {
  friend class ObjectFileLayout;
  friend class Layout;
  friend class ExeLayout;
  public:
  friend struct ::Profiler;

  //! Configuration options to tweak the building process
  struct config_t {
    bool dt_hash         = true;
    bool dyn_str         = true;
    bool dynamic_section = true;
    bool fini_array      = true;
    bool gnu_hash        = true;
    bool init_array      = true;
    bool interpreter     = true;
    bool jmprel          = true;
    bool notes           = true;
    bool preinit_array   = true;
    bool rela            = true;
    bool static_symtab   = true;
    bool sym_verdef      = true;
    bool sym_verneed     = true;
    bool sym_versym      = true;
    bool symtab          = true;

    bool force_relocate  = false; /// Force to relocating all the ELF structures that are supported by LIEF (mostly for testing)
  };

  Builder(Binary& binary);

  Builder() = delete;
  ~Builder();

  //! Perform the build of the provided ELF binary
  void build();

  //! Tweak the ELF builder with the provided config parameter
  inline Builder& set_config(config_t conf) {
    config_ = std::move(conf);
    return *this;
  }

  inline config_t& config() {
    return config_;
  }

  //! Return the built ELF binary as a byte vector
  const std::vector<uint8_t>& get_build();

  //! Write the built ELF binary in the ``filename`` given in parameter
  void write(const std::string& filename) const;

  //! Write the built ELF binary in the stream ``os`` given in parameter
  void write(std::ostream& os) const;

  protected:
  template<typename ELF_T>
  ok_error_t build();

  template<typename ELF_T>
  ok_error_t build_relocatable();

  template<typename ELF_T>
  ok_error_t build_exe_lib();

  template<typename ELF_T>
  ok_error_t build(const Header& header);

  template<typename ELF_T>
  ok_error_t build_sections();

  template<typename ELF_T>
  ok_error_t build_segments();

  template<typename ELF_T>
  ok_error_t build_static_symbols();

  template<typename ELF_T>
  ok_error_t build_dynamic();

  template<typename ELF_T>
  ok_error_t build_dynamic_section();

  template<typename ELF_T>
  ok_error_t build_dynamic_symbols();

  template<typename ELF_T>
  ok_error_t build_obj_symbols();

  template<typename ELF_T>
  ok_error_t build_dynamic_relocations();

  template<typename ELF_T>
  ok_error_t build_pltgot_relocations();

  template<typename ELF_T>
  ok_error_t build_section_relocations();

  uint32_t sort_dynamic_symbols();

  template<typename ELF_T>
  ok_error_t build_hash_table();

  template<typename ELF_T>
  ok_error_t build_symbol_hash();

  ok_error_t build_empty_symbol_gnuhash();

  template<typename ELF_T>
  ok_error_t build_symbol_requirement();

  template<typename ELF_T>
  ok_error_t build_symbol_definition();

  template<typename ELF_T>
  ok_error_t build_symbol_version();

  template<typename ELF_T>
  ok_error_t build_interpreter();

  template<typename ELF_T>
  ok_error_t build_notes();

  ok_error_t build(const Note& note, std::set<Section*>& sections);

  template<typename ELF_T>
  ok_error_t build_overlay();

  bool should_swap() const;

  template<class ELF_T>
  ok_error_t process_object_relocations();

  config_t config_;
  mutable vector_iostream ios_;
  Binary* binary_{nullptr};
  std::unique_ptr<Layout> layout_;

};

} // namespace ELF
} // namespace LIEF




#endif
