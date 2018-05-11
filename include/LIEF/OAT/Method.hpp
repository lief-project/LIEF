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
#ifndef LIEF_OAT_METHOD_H_
#define LIEF_OAT_METHOD_H_

#include "LIEF/OAT/type_traits.hpp"
#include "LIEF/OAT/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/DEX.hpp"

namespace LIEF {
namespace OAT {
class Parser;
class Class;

class LIEF_API Method : public Object {
  friend class Parser;
  public:

  //! Container for the Quick Code
  using quick_code_t = std::vector<uint8_t>;

  public:
  Method(void);
  Method(DEX::Method* method, Class* oat_class, const std::vector<uint8_t>& code = {});
  Method(const Method&);
  Method& operator=(const Method&);


  //! Method's name
  std::string name(void) const;

  //! OAT Class associated with this Method
  const Class& oat_class(void) const;
  Class& oat_class(void);

  //! Check if a LIEF::DEX::Method is associated with
  //! this Method
  bool has_dex_method(void) const;

  //! LIEF::DEX::Method associated (if any)
  const DEX::Method& dex_method(void) const;
  DEX::Method& dex_method(void);

  //! True if the optimization is DEX
  bool is_dex2dex_optimized(void) const;

  // True if the optimization is native
  bool is_compiled(void) const;

  const DEX::dex2dex_method_info_t& dex2dex_info(void) const;

  //! Quick code associated with the method
  const quick_code_t& quick_code(void) const;
  void quick_code(const quick_code_t& code);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Method& rhs) const;
  bool operator!=(const Method& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Method& meth);

  virtual ~Method(void);

  private:
  DEX::Method* dex_method_{nullptr};
  Class* class_{nullptr};

  quick_code_t quick_code_;
};

} // Namespace OAT
} // Namespace LIEF
#endif
