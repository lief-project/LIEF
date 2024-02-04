/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_PE_RESOURCE_ICON_H
#define LIEF_PE_RESOURCE_ICON_H
#include <ostream>
#include <sstream>
#include <climits>
#include <vector>

#include "LIEF/visibility.h"

#include "LIEF/span.hpp"
#include "LIEF/Object.hpp"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;

namespace details {
struct pe_resource_icon_group;
struct pe_icon_header;
}

class LIEF_API ResourceIcon : public Object {

  friend class ResourcesManager;

  public:
  ResourceIcon();
  ResourceIcon(const details::pe_resource_icon_group& header);
  ResourceIcon(const details::pe_icon_header& header);

  ResourceIcon(const ResourceIcon&);
  ResourceIcon& operator=(const ResourceIcon&);

  ~ResourceIcon() override;

  //! Id associated with the icon
  uint32_t id() const;

  //! Language associated with the icon
  uint32_t lang() const;

  //! Sub language associated with the icon
  uint32_t sublang() const;

  //! Width in pixels of the image
  uint8_t width() const;

  //! Height in pixels of the image
  uint8_t height() const;

  //! Number of colors in image (0 if >=8bpp)
  uint8_t color_count() const;

  //! Reserved (must be 0)
  uint8_t reserved() const;

  //! Color Planes
  uint16_t planes() const;

  //! Bits per pixel
  uint16_t bit_count() const;

  //! Size in bytes of the image
  uint32_t size() const;

  //! Pixels of the image (as bytes)
  span<const uint8_t> pixels() const;

  void id(uint32_t id);
  void lang(uint32_t lang);
  void sublang(uint32_t sublang);
  void width(uint8_t width);
  void height(uint8_t height);
  void color_count(uint8_t color_count);
  void reserved(uint8_t reserved);
  void planes(uint16_t planes);
  void bit_count(uint16_t bit_count);
  void pixels(const std::vector<uint8_t>& pixels);

  //! Save the icon to the given filename
  //!
  //! @param[in] filename Path to file in which the icon will be saved
  void save(const std::string& filename) const;

  void accept(Visitor& visitor) const override;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceIcon& entry);

  private:
  uint8_t              width_ = 0;
  uint8_t              height_ = 0;
  uint8_t              color_count_ = 0;
  uint8_t              reserved_ = 0;
  uint16_t             planes_ = 0;
  uint16_t             bit_count_ = 0;
  uint32_t             id_ = UINT_MAX;
  uint32_t             lang_ = /* LANG_NEUTRAL */0;
  uint32_t             sublang_ = 0 /* SUBLANG_NEUTRAL */;
  std::vector<uint8_t> pixels_;
};

}
}


#endif
