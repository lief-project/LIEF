/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/errors.hpp"

struct Profiler;

namespace LIEF {
namespace PE {

//! Class that is used to rebuild a raw PE binary from a PE::Binary object
class LIEF_API Builder {
  public:
  friend struct ::Profiler;

  Builder() = delete;
  Builder(Binary& binary);
  ~Builder();

  //! Perform the build process
  ok_error_t build();

  //! @brief Construct a ``jmp [address] @ from``.
  //!
  //! It is used when patching import table
  template<typename PE_T>
  static std::vector<uint8_t> build_jmp(uint64_t from, uint64_t address);


  //! @brief Construct a ``jmp far address @ from``.
  //!
  //! It is used for hooking
  template<typename PE_T>
  static std::vector<uint8_t> build_jmp_hook(uint64_t from, uint64_t address);

  //! @brief Rebuild the import table in new section
  Builder& build_imports(bool flag = true);

  //! @brief Patch the original import table in order to
  //! redirect functions to the new import table.
  //!
  //! This setting should be used with LIEF::PE::Builder::build_imports set to ``true``
  Builder& patch_imports(bool flag = true);

  //! @brief Rebuild the relocation table in another section
  Builder& build_relocations(bool flag = true);

  //! @brief Rebuild TLS object in another section
  Builder& build_tls(bool flag = true);

  //! @brief Rebuid the resources in another section
  Builder& build_resources(bool flag);

  //! @brief Rebuild the binary's overlay
  Builder& build_overlay(bool flag);

  //! @brief Rebuild the DOS stub content
  Builder& build_dos_stub(bool flag);

  //! @brief Return the build result
  const std::vector<uint8_t>& get_build();

  //! @brief Write the build result into the ``output`` file
  void write(const std::string& filename) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Builder& b);

  ok_error_t build(const DosHeader& dos_header);
  ok_error_t build(const Header& bHeader);
  ok_error_t build(const OptionalHeader& optional_header);
  ok_error_t build(const DataDirectory& data_directory);
  ok_error_t build(const Section& section);

  protected:
  template<typename PE_T>
  ok_error_t build_optional_header(const OptionalHeader& optional_header);

  //! @brief Rebuild Import Table
  // TODO: Bug with x86
  template<typename PE_T>
  void build_import_table();

  template<typename PE_T>
  ok_error_t build_tls();

  ok_error_t build_relocation();
  ok_error_t build_resources();
  ok_error_t build_overlay();
  ok_error_t build_dos_stub();

  ok_error_t compute_resources_size(ResourceNode& node, uint32_t *header_size,
                              uint32_t *data_size, uint32_t *name_size);

  ok_error_t construct_resources(ResourceNode& node, std::vector<uint8_t>* content,
                           uint32_t* offset_header, uint32_t* offset_data, uint32_t* offset_name,
                           uint32_t base_rva, uint32_t depth);


  mutable vector_iostream ios_;
  Binary* binary_ = nullptr;

  bool build_imports_ = false;
  bool patch_imports_ = false;
  bool build_relocations_ = false;
  bool build_tls_ = false;
  bool build_resources_ = false;
  bool build_overlay_ = true;
  bool build_dos_stub_ = true;

};

}
}
#endif
