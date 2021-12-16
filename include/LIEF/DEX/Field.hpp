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
  Field();
  Field(const std::string& name, Class* parent = nullptr);

  Field(const Field&);
  Field& operator=(const Field&);

  //! Name of the Field
  const std::string& name() const;

  //! True if a class is associated with this field
  bool has_class() const;

  //! Class associated with this Field
  const Class& cls() const;
  Class& cls();

  //! Index in the DEX Fields pool
  size_t index() const;

  //! True if this field is a static one.
  bool is_static() const;

  //! Field's prototype
  const Type& type() const;
  Type& type();

  virtual void accept(Visitor& visitor) const override;

  bool has(ACCESS_FLAGS f) const;

  access_flags_list_t access_flags() const;

  bool operator==(const Field& rhs) const;
  bool operator!=(const Field& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Field& mtd);

  virtual ~Field();

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
