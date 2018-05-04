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
#ifndef LIEF_OAT_HEADER_H_
#define LIEF_OAT_HEADER_H_
#include <functional>
#include "LIEF/OAT/type_traits.hpp"
#include "LIEF/OAT/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

namespace LIEF {
namespace OAT {
class Parser;

class LIEF_API Header : public Object {
  friend class Parser;

  public:
  using magic_t               = std::array<uint8_t, sizeof(oat_magic)>;
  using key_values_t          = std::map<HEADER_KEYS, std::string>;
  using it_key_values_t       = ref_iterator< std::vector< std::pair<HEADER_KEYS, std::reference_wrapper<std::string>> > >;
  using it_const_key_values_t = const_ref_iterator<std::vector<std::pair<HEADER_KEYS, std::string>>>;

  //! @brief Iterator type over
  using keys_t   = std::vector<HEADER_KEYS>;
  using values_t = std::vector<std::string>;

  public:
  //! Return the string value associated with the given key
  static std::string key_to_string(HEADER_KEYS key);

  public:
  Header(void);
  Header(const Header&);
  Header& operator=(const Header&);

  template<class T>
  LIEF_LOCAL Header(const T* header);

  //! Magic value: ``oat``
  Header::magic_t magic(void) const;

  //! OAT version
  oat_version_t version(void) const;

  uint32_t checksum(void) const;

  INSTRUCTION_SETS instruction_set(void) const;
  // TODO instruction_set_features_bitmap_(void) const;


  uint32_t nb_dex_files(void) const;

  // Since OAT 131
  uint32_t oat_dex_files_offset(void) const;

  uint32_t executable_offset(void) const;
  uint32_t i2i_bridge_offset(void) const;
  uint32_t i2c_code_bridge_offset(void) const;
  uint32_t jni_dlsym_lookup_offset(void) const;

  uint32_t quick_generic_jni_trampoline_offset(void) const;
  uint32_t quick_imt_conflict_trampoline_offset(void) const;
  uint32_t quick_resolution_trampoline_offset(void) const;
  uint32_t quick_to_interpreter_bridge_offset(void) const;

  int32_t image_patch_delta(void) const;

  uint32_t image_file_location_oat_checksum(void) const;
  uint32_t image_file_location_oat_data_begin(void) const;

  uint32_t key_value_size(void) const;

  it_key_values_t       key_values(void);
  it_const_key_values_t key_values(void) const;

  keys_t keys(void) const;
  values_t values(void) const;

  const std::string& get(HEADER_KEYS key) const;
  std::string& get(HEADER_KEYS key);

  Header& set(HEADER_KEYS key, const std::string& value);

  const std::string& operator[](HEADER_KEYS key) const;
  std::string& operator[](HEADER_KEYS key);

  void magic(const magic_t& magic);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Header& rhs) const;
  bool operator!=(const Header& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

  private:
  magic_t magic_;
  oat_version_t version_;
  uint32_t checksum_;
  INSTRUCTION_SETS instruction_set_;
  uint32_t instruction_set_features_bitmap_;
  uint32_t dex_file_count_;
  uint32_t oat_dex_files_offset_; // Since OAT 131 / Android 8.1.0
  uint32_t executable_offset_;
  uint32_t i2i_bridge_offset_;
  uint32_t i2c_code_bridge_offset_;
  uint32_t jni_dlsym_lookup_offset_;

  uint32_t quick_generic_jni_trampoline_offset_;
  uint32_t quick_imt_conflict_trampoline_offset_;
  uint32_t quick_resolution_trampoline_offset_;
  uint32_t quick_to_interpreter_bridge_offset_;

  int32_t image_patch_delta_;

  uint32_t image_file_location_oat_checksum_;
  uint32_t image_file_location_oat_data_begin_;

  uint32_t key_value_store_size_;

  key_values_t dex2oat_context_;


};

}
}

#endif
