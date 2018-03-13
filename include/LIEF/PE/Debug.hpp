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
#ifndef LIEF_PE_DEBUG_H_
#define LIEF_PE_DEBUG_H_

#include <string>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/CodeView.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class LIEF_API Debug : public Object {

  friend class Parser;
  friend class Builder;

  public:
    Debug(void);
    Debug(const pe_debug* debug_s);
    Debug(const Debug& copy);
    Debug& operator=(Debug copy);

    void swap(Debug& other);

    virtual ~Debug(void);

    //! Reserved should be 0
    uint32_t characteristics(void) const;

    //! The time and date that the debug data was created.
    uint32_t timestamp(void) const;

    //! The major version number of the debug data format.
    uint16_t major_version(void) const;

    //! The minor version number of the debug data format.
    uint16_t minor_version(void) const;

    //! The format DEBUG_TYPES of the debugging information
    DEBUG_TYPES type(void) const;

    //! Size of the debug data
    uint32_t sizeof_data(void) const;

    //! Address of the debug data relative to the image base
    uint32_t addressof_rawdata(void) const;

    //! File offset of the debug data
    uint32_t pointerto_rawdata(void) const;

    bool has_code_view(void) const;

    const CodeView& code_view(void) const;
    CodeView& code_view(void);


    void characteristics(uint32_t characteristics);
    void timestamp(uint32_t timestamp);
    void major_version(uint16_t major_version);
    void minor_version(uint16_t minor_version);
    void type(DEBUG_TYPES new_type);
    void sizeof_data(uint32_t sizeof_data);
    void addressof_rawdata(uint32_t addressof_rawdata);
    void pointerto_rawdata(uint32_t pointerto_rawdata);


    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Debug& rhs) const;
    bool operator!=(const Debug& rhs) const;


    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Debug& entry);

  private:
    uint32_t    characteristics_;
    uint32_t    timestamp_;
    uint16_t    majorversion_;
    uint16_t    minorversion_;
    DEBUG_TYPES type_;
    uint32_t    sizeof_data_;
    uint32_t    addressof_rawdata_;
    uint32_t    pointerto_rawdata_;

    CodeView* code_view_;



};
}
}
#endif
