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
#ifndef LIEF_VDEX_TYPE_TRAITS_H_
#define LIEF_VDEX_TYPE_TRAITS_H_

#include <vector>
#include "LIEF/iterators.hpp"
#include "LIEF/OAT.hpp"

namespace LIEF {
namespace VDEX {
using vdex_version_t = uint32_t;
using dex2dex_info_t = LIEF::OAT::dex2dex_info_t;
}
}

#endif
