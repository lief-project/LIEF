
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
#ifndef LIEF_PE_DEBUG_H
#define LIEF_PE_DEBUG_H
#include <cstdint>
#include <ostream>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {
class Parser;
class Builder;

namespace details {
struct pe_debug;
}

//! This class represents a generic entry in the debug data directory.
//! For known types, this class is extended to provide a dedicated API
//! (see: ! CodeCodeView)
class LIEF_API Debug : public Object {
  friend class Parser;
  friend class Builder;

  public:
  //! The entry types
  enum class TYPES {
    UNKNOWN               = 0,
    COFF                  = 1, ///< COFF debug information
    CODEVIEW              = 2, ///< CodeView debug information (pdb & cie)
    FPO                   = 3, ///< Frame pointer omission information
    MISC                  = 4, ///< CodeView Debug Information
    EXCEPTION             = 5, ///< A copy of .pdata section.
    FIXUP                 = 6, ///< Reserved.
    OMAP_TO_SRC           = 7, ///< The mapping from an RVA in image to an RVA in source image.
    OMAP_FROM_SRC         = 8, ///< The mapping from an RVA in source image to an RVA in image.
    BORLAND               = 9, ///< Reserved for Borland.
    RESERVED10            = 10, ///< Reserved
    CLSID                 = 11, ///< Reserved
    VC_FEATURE            = 12,
    POGO                  = 13, ///< Profile Guided Optimization metadata
    ILTCG                 = 14,
    MPX                   = 15,
    REPRO                 = 16, ///< PE determinism or reproducibility.
    EX_DLLCHARACTERISTICS = 20,
  };
  Debug() = default;
  Debug(TYPES type) {
    type_ = type;
  }

  Debug(const details::pe_debug& debug_s);
  Debug(const Debug& other) = default;
  Debug& operator=(const Debug& other) = default;

  ~Debug() override = default;

  virtual std::unique_ptr<Debug> clone() const {
    return std::unique_ptr<Debug>(new Debug(*this));
  }

  //! Reserved should be 0
  uint32_t characteristics() const {
    return characteristics_;
  }

  //! The time and date when the debug data was created.
  uint32_t timestamp() const {
    return timestamp_;
  }

  //! The major version number of the debug data format.
  uint16_t major_version() const {
    return major_version_;
  }

  //! The minor version number of the debug data format.
  uint16_t minor_version() const {
    return minor_version_;
  }

  //! The format DEBUG_TYPES of the debugging information
  TYPES type() const {
    return type_;
  }

  //! Size of the debug data
  uint32_t sizeof_data() const {
    return sizeof_data_;
  }

  //! Address of the debug data relative to the image base
  uint32_t addressof_rawdata() const {
    return addressof_rawdata_;
  }

  //! File offset of the debug data
  uint32_t pointerto_rawdata() const {
    return pointerto_rawdata_;
  }

  void characteristics(uint32_t characteristics) {
    characteristics_ = characteristics;
  }

  void timestamp(uint32_t timestamp) {
    timestamp_ = timestamp;
  }

  void major_version(uint16_t major_version) {
    major_version_ = major_version;
  }

  void minor_version(uint16_t minor_version) {
    minor_version_ = minor_version;
  }

  void sizeof_data(uint32_t sizeof_data) {
    sizeof_data_ = sizeof_data;
  }

  void addressof_rawdata(uint32_t addressof_rawdata) {
    addressof_rawdata_ = addressof_rawdata;
  }

  void pointerto_rawdata(uint32_t pointerto_rawdata) {
    pointerto_rawdata_ = pointerto_rawdata;
  }

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Debug& entry);

  protected:
  TYPES type_ = TYPES::UNKNOWN;
  uint32_t characteristics_ = 0;
  uint32_t timestamp_ = 0;
  uint16_t major_version_ = 0;
  uint16_t minor_version_ = 0;
  uint32_t sizeof_data_ = 0;
  uint32_t addressof_rawdata_ = 0;
  uint32_t pointerto_rawdata_ = 0;
};

LIEF_API const char* to_string(Debug::TYPES e);

}
}
#endif
