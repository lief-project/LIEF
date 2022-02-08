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
#ifndef LIEF_PE_DEBUG_H_
#define LIEF_PE_DEBUG_H_

#include <string>
#include <iostream>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;
class CodeView;
class Pogo;

namespace details {
struct pe_debug;
}

class LIEF_API Debug : public Object {

  friend class Parser;
  friend class Builder;

  public:
  Debug();
  Debug(const details::pe_debug& debug_s);
  Debug(const Debug& copy);
  Debug& operator=(Debug copy);

  void swap(Debug& other);

  virtual ~Debug();

  //! Reserved should be 0
  uint32_t characteristics() const;

  //! The time and date that the debug data was created.
  uint32_t timestamp() const;

  //! The major version number of the debug data format.
  uint16_t major_version() const;

  //! The minor version number of the debug data format.
  uint16_t minor_version() const;

  //! The format DEBUG_TYPES of the debugging information
  DEBUG_TYPES type() const;

  //! Size of the debug data
  uint32_t sizeof_data() const;

  //! Address of the debug data relative to the image base
  uint32_t addressof_rawdata() const;

  //! File offset of the debug data
  uint32_t pointerto_rawdata() const;

  bool has_code_view() const;

  const CodeView* code_view() const;
  CodeView* code_view();

  bool has_pogo() const;

  const Pogo* pogo() const;
  Pogo* pogo();

  void characteristics(uint32_t characteristics);
  void timestamp(uint32_t timestamp);
  void major_version(uint16_t major_version);
  void minor_version(uint16_t minor_version);
  void type(DEBUG_TYPES new_type);
  void sizeof_data(uint32_t sizeof_data);
  void addressof_rawdata(uint32_t addressof_rawdata);
  void pointerto_rawdata(uint32_t pointerto_rawdata);

  void accept(Visitor& visitor) const override;

  bool operator==(const Debug& rhs) const;
  bool operator!=(const Debug& rhs) const;


  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Debug& entry);

  private:
  uint32_t    characteristics_ = 0;
  uint32_t    timestamp_ = 0;
  uint16_t    majorversion_ = 0;
  uint16_t    minorversion_ = 0;
  DEBUG_TYPES type_ = DEBUG_TYPES::IMAGE_DEBUG_TYPE_UNKNOWN;
  uint32_t    sizeof_data_ = 0;
  uint32_t    addressof_rawdata_ = 0;
  uint32_t    pointerto_rawdata_ = 0;

  std::unique_ptr<CodeView> code_view_;
  std::unique_ptr<Pogo> pogo_;
};
}
}
#endif
