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
#ifndef LIEF_MACHO_VISITOR_JSONS_H_
#define LIEF_MACHO_VISITOR_JSONS_H_

#include "LIEF/config.h"

#ifdef LIEF_JSON_SUPPORT

#include "LIEF/visibility.h"
#include "LIEF/visitors/json.hpp"
#include "LIEF/MachO.hpp"

namespace LIEF {
namespace MachO {

LIEF_API json to_json(const Object& v);
LIEF_API std::string to_json_str(const Object& v);


class LIEF_API JsonVisitor : public LIEF::JsonVisitor {
  public:
  using LIEF::JsonVisitor::JsonVisitor;

  public:
  virtual void visit(const Binary& binary)                        override;
  virtual void visit(const Header& header)                        override;
  virtual void visit(const LoadCommand& cmd)                      override;
  virtual void visit(const UUIDCommand& uuid)                     override;
  virtual void visit(const SymbolCommand& symbol)                 override;
  virtual void visit(const SegmentCommand& segment)               override;
  virtual void visit(const Section& section)                      override;
  virtual void visit(const MainCommand& maincmd)                  override;
  virtual void visit(const DynamicSymbolCommand& dynamic_symbol)  override;
  virtual void visit(const DylinkerCommand& dylinker)             override;
  virtual void visit(const DylibCommand& dylib)                   override;
  virtual void visit(const ThreadCommand& threadcmd)              override;
  virtual void visit(const RPathCommand& rpath)                   override;
  virtual void visit(const Symbol& symbol)                        override;
  virtual void visit(const Relocation& relocation)                override;
  virtual void visit(const RelocationObject& robject)             override;
  virtual void visit(const RelocationDyld& rdyld)                 override;
  virtual void visit(const BindingInfo& binding)                  override;
  virtual void visit(const ExportInfo& einfo)                     override;
  virtual void visit(const FunctionStarts& fs)                    override;
  virtual void visit(const CodeSignature& cs)                     override;
  virtual void visit(const DataInCode& dic)                       override;
  virtual void visit(const DataCodeEntry& dce)                    override;
  virtual void visit(const SourceVersion& sv)                     override;
  virtual void visit(const VersionMin& vmin)                      override;
};

}
}

#endif // LIEF_JSON_SUPPORT

#endif
