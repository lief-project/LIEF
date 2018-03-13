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
#ifndef LIEF_MACHO_BUIDLER_H_
#define LIEF_MACHO_BUIDLER_H_

#include <algorithm>
#include <vector>
#include <vector>
#include <memory>

#include "LIEF/visibility.h"
#include "LIEF/exception.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {


class LIEF_API Builder {
  public:
    Builder(Binary *binary);
    Builder(std::vector<Binary*> binaries);

    Builder(void) = delete;
    ~Builder(void);

    const std::vector<uint8_t>& get_build(void);
    void write(const std::string& filename) const;
    static void write(Binary *binary, const std::string& filename);

  private:
    void build(void);
    void build_header(void);
    void build_load_commands(void);

    template <typename T>
    void build_segments(void);

    void build_uuid(void);

    template <typename T>
    void build_symbols(void);

    std::vector<Binary*> binaries_;
    Binary*              binary_;
    std::vector<uint8_t> rawBinary_;
};

} // namespace MachO
} // namespace LIEF
#endif
