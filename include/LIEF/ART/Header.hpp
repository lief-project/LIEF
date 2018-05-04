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
#ifndef LIEF_ART_HEADER_H_
#define LIEF_ART_HEADER_H_

#include "LIEF/ART/type_traits.hpp"
#include "LIEF/ART/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

namespace LIEF {
namespace ART {
class Parser;

class LIEF_API Header : public Object {
  friend class Parser;

  public:
  using magic_t = std::array<uint8_t, 4>;

  Header(void);

  template<class T>
  LIEF_LOCAL Header(const T* header);

  Header(const Header&);
  Header& operator=(const Header&);

  magic_t magic(void) const;
  art_version_t version(void) const;

  uint32_t image_begin(void) const;
  uint32_t image_size(void) const;

  uint32_t oat_checksum(void) const;

  uint32_t oat_file_begin(void) const;
  uint32_t oat_file_end(void) const;

  uint32_t oat_data_begin(void) const;
  uint32_t oat_data_end(void) const;

  int32_t patch_delta(void) const;

  uint32_t image_roots(void) const;

  uint32_t pointer_size(void) const;
  bool compile_pic(void) const;

  uint32_t nb_sections(void) const;
  uint32_t nb_methods(void) const;

  uint32_t boot_image_begin(void) const;
  uint32_t boot_image_size(void) const;

  uint32_t boot_oat_begin(void) const;
  uint32_t boot_oat_size(void) const;

  STORAGE_MODES storage_mode(void) const;

  uint32_t data_size(void) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Header& rhs) const;
  bool operator!=(const Header& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

  virtual ~Header(void);

  private:
  magic_t       magic_;
  art_version_t version_;

  uint32_t image_begin_;
  uint32_t image_size_;

  uint32_t oat_checksum_;

  uint32_t oat_file_begin_;
  uint32_t oat_file_end_;

  uint32_t oat_data_begin_;
  uint32_t oat_data_end_;

  int32_t patch_delta_;
  uint32_t image_roots_;

  uint32_t pointer_size_;

  bool compile_pic_;

  uint32_t nb_sections_;
  uint32_t nb_methods_;

  bool is_pic_;

  // From ART 29
  // ===========
  uint32_t boot_image_begin_;
  uint32_t boot_image_size_;

  uint32_t boot_oat_begin_;
  uint32_t boot_oat_size_;

  STORAGE_MODES storage_mode_;

  uint32_t data_size_;
};

} // Namespace ART
} // Namespace LIEF

#endif
