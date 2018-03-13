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
#ifndef LIEF_MACHO_PARSER_CONFIG_H_
#define LIEF_MACHO_PARSER_CONFIG_H_
#include "LIEF/visibility.h"

namespace LIEF {
namespace MachO {

class LIEF_API ParserConfig {
  public:
    ParserConfig(void);
    ParserConfig& operator=(const ParserConfig&);
    ParserConfig(const ParserConfig&);
    ~ParserConfig(void);

    //! @brief Return a configuration so that the all objects supported by
    //! LIEF are parsed
    //!
    //! With this configuration:
    //! * ``parse_dyldinfo_deeply`` is set to ``true``
    static ParserConfig deep(void);

    //! Return a configuration so that the parsing is quick
    //!
    //! With this configuration:
    //! * ``parse_dyldinfo_deeply`` is set to ``false``
    static ParserConfig quick(void);

    //! @brief If ``flag`` is set to ``true``,
    //! Exports, Bindings and Rebases opcodes are
    //! parsed.
    //!
    //! @warning Enabling this flag can slow down the parsing
    ParserConfig& parse_dyldinfo_deeply(bool flag);

    //! @brief Whether or not bindings, exports, and rebases are parsed
    bool parse_dyldinfo_deeply(void) const;

  private:
    bool dyldinfo_deeply_;
};

}
}
#endif
