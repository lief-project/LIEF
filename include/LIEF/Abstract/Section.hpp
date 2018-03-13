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
#ifndef LIEF_ABSTRACT_SECTION_H_
#define LIEF_ABSTRACT_SECTION_H_

#include <string>
#include <vector>
#include <memory>
#include <iostream>

#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
class LIEF_API Section : public Object {
  public:

    static constexpr size_t npos = -1;

    Section(void);
    Section(const std::string& name);

    virtual ~Section(void);

    Section& operator=(const Section&);
    Section(const Section&);

    //! @brief section's name
    virtual const std::string& name(void) const;

    //! @brief section's content
    virtual std::vector<uint8_t> content(void) const;

    //! @brief section's size (size in the binary)
    virtual void size(uint64_t size);

    //! @brief section's size (size in the binary)
    virtual uint64_t size(void) const;

    //! @brief offset in the binary
    virtual uint64_t offset(void) const;

    //! @brief Address where the section should be mapped
    virtual uint64_t virtual_address(void) const;

    virtual void virtual_address(uint64_t virtual_address);

    //! @brief Set the section's name
    virtual void name(const std::string& name);

    //! @brief Set section content
    virtual void content(const std::vector<uint8_t>& data);

    virtual void offset(uint64_t offset);

    //! @brief Section's entropy
    double entropy(void) const;

    // Search functions
    // ================
    size_t search(uint64_t integer, size_t pos, size_t size) const;
    size_t search(const std::vector<uint8_t>& pattern, size_t pos = 0) const;
    size_t search(const std::string& pattern, size_t pos = 0) const;
    size_t search(uint64_t integer, size_t pos = 0) const;

    // Search all functions
    // ====================
    std::vector<size_t> search_all(uint64_t v, size_t size) const;

    std::vector<size_t> search_all(uint64_t v) const;

    std::vector<size_t> search_all(const std::string& v) const;

    //! @brief Method so that the ``visitor`` can visit us
    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Section& rhs) const;
    bool operator!=(const Section& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Section& entry);

  protected:
    std::string name_;
    uint64_t    virtual_address_;
    uint64_t    size_;
    uint64_t    offset_;

  private:
    template<typename T>
    std::vector<size_t> search_all_(const T& v) const;


};
}

#endif
