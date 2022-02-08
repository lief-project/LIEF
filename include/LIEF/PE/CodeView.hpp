/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_PE_CODE_VIEW_H_
#define LIEF_PE_CODE_VIEW_H_
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {
class LIEF_API CodeView : public Object {
  public:

  CodeView();
  CodeView(CODE_VIEW_SIGNATURES cv_signature);

  CodeView(const CodeView&);
  CodeView& operator=(const CodeView&);

  virtual CodeView* clone() const = 0;

  //! The Code View signature
  CODE_VIEW_SIGNATURES cv_signature() const;

  void accept(Visitor& visitor) const override;

  bool operator==(const CodeView& rhs) const;
  bool operator!=(const CodeView& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CodeView& entry);

  virtual ~CodeView();

  protected:
  CODE_VIEW_SIGNATURES cv_signature_;
};

} // Namespace PE
} // Namespace LIEF

#endif
