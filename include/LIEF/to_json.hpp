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
#ifndef LIEF_TO_JSON_H_
#define LIEF_TO_JSON_H_

#include "LIEF/config.h"

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/json.hpp"

#include "LIEF/visitors/json.hpp"
#include "LIEF/ELF/json.hpp"
#include "LIEF/PE/json.hpp"
#include "LIEF/Abstract/json.hpp"

#include "LIEF/Abstract.hpp"
#include "LIEF/ELF.hpp"
#include "LIEF/PE.hpp"

namespace LIEF {
//template<class T, class VISITOR = JsonVisitor>
//json to_json(const T& obj) {
//  VISITOR visitor;
//  visitor(obj);
//  return visitor.get();
//}
//
//template<class T, class VISITOR = JsonVisitor>
//std::string to_json_str(const T& obj) {
//  return to_json<T, VISITOR>(obj).dump();
//}

} // namespace LIEF

#endif // LIEF_JSON_SUPPORT

#endif
