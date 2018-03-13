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
#ifndef LIEF_MACHO_VERSION_MIN_COMMAND_H_
#define LIEF_MACHO_VERSION_MIN_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

class LIEF_API VersionMin : public LoadCommand {

  public:
    //! @brief Version is an array of **3** integers
    using version_t = std::array<uint32_t, 3>;

    VersionMin(void);
    VersionMin(const version_min_command *version_cmd);

    VersionMin& operator=(const VersionMin& copy);
    VersionMin(const VersionMin& copy);

    virtual ~VersionMin(void);

    //! @brief Return the version as an array
    const VersionMin::version_t& version(void) const;
    void version(const VersionMin::version_t& version);

    //! @brief Return the sdk as an array
    const VersionMin::version_t& sdk(void) const;
    void sdk(const VersionMin::version_t& sdk);

    bool operator==(const VersionMin& rhs) const;
    bool operator!=(const VersionMin& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    VersionMin::version_t version_;
    VersionMin::version_t sdk_;
};

}
}
#endif
