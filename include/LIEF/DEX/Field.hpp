#ifndef LIEF_DEX_FIELD_H_
#define LIEF_DEX_FIELD_H_

#include "LIEF/DEX/type_traits.hpp"
#include "LIEF/DEX/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

#include "LIEF/DEX/Type.hpp"

namespace LIEF {
namespace DEX {
class Parser;
class Class;

class LIEF_API Field : public Object {
  friend class Parser;
  public:
  using access_flags_list_t = std::vector<ACCESS_FLAGS>;

  public:
  Field(void);
  Field(const std::string& name, Class* parent = nullptr);

  Field(const Field&);
  Field& operator=(const Field&);

  //! Name of the Field
  const std::string& name(void) const;

  //! True if a class is associated with this field
  bool has_class(void) const;

  //! Class associated with this Field
  const Class& cls(void) const;
  Class& cls(void);

  //! Index in the DEX Fields pool
  size_t index(void) const;

  //! True if this field is a static one.
  bool is_static(void) const;

  //! Field's prototype
  const Type& type(void) const;
  Type& type(void);

  virtual void accept(Visitor& visitor) const override;

  bool has(ACCESS_FLAGS f) const;

  access_flags_list_t access_flags(void) const;

  bool operator==(const Field& rhs) const;
  bool operator!=(const Field& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Field& mtd);

  virtual ~Field(void);

  private:
  void set_static(bool v);

  private:
  std::string name_;
  Class* parent_{nullptr};
  Type* type_{nullptr};
  uint32_t access_flags_ = 0;
  uint32_t original_index_ = -1u;
  bool is_static_ = false;

};

} // Namespace DEX
} // Namespace LIEF
#endif
