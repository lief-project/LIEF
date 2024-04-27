#pragma once
#include "LIEF/PE/signature/attributes/ContentType.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_ContentType : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::ContentType;
  PE_ContentType(const lief_t& base) : PE_Attribute(base) {}

  std::string oid() const {
    return impl().oid();
  }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
