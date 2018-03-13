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
#ifndef LIEF_ABSTRACT_JSON_H_
#define LIEF_ABSTRACT_JSON_H_

#include "LIEF/config.h"

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/visibility.h"
#include "LIEF/visitors/json.hpp"
#include "LIEF/Abstract.hpp"

namespace LIEF {

LIEF_API json to_json_from_abstract(const Object& v);
LIEF_API std::string to_json_str_from_abstract(const Object& v);


class LIEF_API AbstractJsonVisitor : public LIEF::JsonVisitor {
  public:
  using LIEF::JsonVisitor::JsonVisitor;

  public:
  virtual void visit(const Binary& binary)         override;
  virtual void visit(const Header& header)         override;
  virtual void visit(const Section& section)       override;
  virtual void visit(const Symbol& symbol)         override;
  virtual void visit(const Relocation& relocation) override;
};

}

#endif // LIEF_JSON_SUPPORT

#endif
