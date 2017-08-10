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
#ifndef LIEF_VISITOR_JSONS_H_
#define LIEF_VISITOR_JSONS_H_

#include "LIEF/config.h"

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/visibility.h"
#include "LIEF/Visitor.hpp"
#include "LIEF/json.hpp"

namespace LIEF {
class DLL_PUBLIC JsonVisitor : public Visitor {

  public:
  using LIEF::Visitor::visit;

  JsonVisitor(void);
  JsonVisitor(const json& node);
  JsonVisitor(const JsonVisitor&);
  JsonVisitor& operator=(const JsonVisitor&);

  virtual void visit(const Binary&  binary)  override;
  virtual void visit(const Header&  header)  override;
  virtual void visit(const Section& section) override;
  virtual void visit(const Symbol&  symbol)  override;

  const json& get(void) const;

  protected:
  json node_;


};

}

#endif // LIEF_JSON_SUPPORT

#endif
