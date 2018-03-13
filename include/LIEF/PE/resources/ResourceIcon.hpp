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
#ifndef LIEF_PE_RESOURCE_ICON_H_
#define LIEF_PE_RESOURCE_ICON_H_
#include <iostream>
#include <sstream>

#include "LIEF/visibility.h"

#include "LIEF/Object.hpp"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {
class ResourcesManager;

class LIEF_API ResourceIcon : public Object {

  friend class ResourcesManager;

  public:
  ResourceIcon(void);
  ResourceIcon(const pe_resource_icon_group *header);
  ResourceIcon(const pe_icon_header *header);

  ResourceIcon(const std::string& iconpath);

  ResourceIcon(const ResourceIcon&);
  ResourceIcon& operator=(const ResourceIcon&);

  virtual ~ResourceIcon(void);

  //! @brief Id associated with the icon
  uint32_t id(void) const;

  //! @brief Language associated with the icon
  RESOURCE_LANGS lang(void) const;

  //! @brief Sub language associated with the icon
  RESOURCE_SUBLANGS sublang(void) const;

  //! @brief Width in pixels of the image
  uint8_t width(void) const;

  //! @brief Height in pixels of the image
  uint8_t height(void) const;

  //! @brief Number of colors in image (0 if >=8bpp)
  uint8_t color_count(void) const;

  //! @brief Reserved (must be 0)
  uint8_t reserved(void) const;

  //! @brief Color Planes
  uint16_t planes(void) const;

  //! @brief Bits per pixel
  uint16_t bit_count(void) const;

  //! @brief Size in bytes of the image
  uint32_t size(void) const;

  //! @brief Pixels of the image (as bytes)
  const std::vector<uint8_t>& pixels(void) const;

  void id(uint32_t id);
  void lang(RESOURCE_LANGS lang);
  void sublang(RESOURCE_SUBLANGS sublang);
  void width(uint8_t width);
  void height(uint8_t height);
  void color_count(uint8_t color_count);
  void reserved(uint8_t reserved);
  void planes(uint16_t planes);
  void bit_count(uint16_t bit_count);
  void pixels(const std::vector<uint8_t>& pixels);

  //! @brief Save the icon to the given filename
  //!
  //! @param[in] filename Path to file in which the icon will be saved
  void save(const std::string& filename) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const ResourceIcon& rhs) const;
  bool operator!=(const ResourceIcon& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const ResourceIcon& entry);

  private:
  uint8_t              width_;
  uint8_t              height_;
  uint8_t              color_count_;
  uint8_t              reserved_;
  uint16_t             planes_;
  uint16_t             bit_count_;
  uint32_t             id_;
  RESOURCE_LANGS       lang_;
  RESOURCE_SUBLANGS    sublang_;
  std::vector<uint8_t> pixels_;


};




}
}


#endif
