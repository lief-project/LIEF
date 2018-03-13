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
#ifndef LIEF_PE_TLS_H_
#define LIEF_PE_TLS_H_

#include <vector>
#include <iostream>
#include <memory>
#include <utility>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/Section.hpp"


namespace LIEF {
namespace PE {

class Parser;
class Builder;

class LIEF_API TLS : public Object {
  friend class Parser;
  friend class Builder;

  public:

    TLS(void);
    TLS(const pe32_tls *header);
    TLS(const pe64_tls *header);
    virtual ~TLS(void);


    TLS(const TLS& copy);
    TLS& operator=(TLS copy);
    void swap(TLS& other);

    const std::vector<uint64_t>&  callbacks(void) const;
    std::pair<uint64_t, uint64_t> addressof_raw_data(void) const;
    uint64_t                      addressof_index(void) const;
    uint64_t                      addressof_callbacks(void) const;
    uint32_t                      sizeof_zero_fill(void) const;
    uint32_t                      characteristics(void) const;
    const std::vector<uint8_t>&   data_template(void) const;

    bool                          has_data_directory(void) const;
    DataDirectory&                directory(void);
    const DataDirectory&          directory(void) const;

    bool                          has_section(void) const;
    Section&                      section(void);
    const Section&                section(void) const;

    void callbacks(const std::vector<uint64_t>& callbacks);
    void addressof_raw_data(std::pair<uint64_t, uint64_t> VAOfRawData);
    void addressof_index(uint64_t addressOfIndex);
    void addressof_callbacks(uint64_t addressOfCallbacks);
    void sizeof_zero_fill(uint32_t sizeOfZeroFill);
    void characteristics(uint32_t characteristics);
    void data_template(const std::vector<uint8_t>& dataTemplate);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const TLS& rhs) const;
    bool operator!=(const TLS& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const TLS& entry);

  private:
    std::vector<uint64_t>         callbacks_;
    std::pair<uint64_t, uint64_t> VAOfRawData_;
    uint64_t                      addressof_index_;
    uint64_t                      addressof_callbacks_;
    uint32_t                      sizeof_zero_fill_;
    uint32_t                      characteristics_;
    DataDirectory*                directory_;
    Section*                      section_;
    std::vector<uint8_t>          data_template_;

};
}
}
#endif
